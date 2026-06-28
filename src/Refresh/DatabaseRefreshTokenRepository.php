<?php

declare(strict_types=1);

namespace Lukk\Refresh;

use Closure;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Lukk;
use Lukk\Support\RefreshTokenRecord;

/**
 * Default storage: the refresh_tokens table via Eloquent. The model is
 * resolved through Lukk::refreshTokenModel() so apps can swap it.
 */
class DatabaseRefreshTokenRepository implements RefreshTokenRepository
{
    public function transaction(Closure $callback): mixed
    {
        return DB::transaction($callback);
    }

    public function findByHashForUpdate(string $hash): ?RefreshTokenRecord
    {
        // Non-locking existence check first: a SELECT ... FOR UPDATE on an absent
        // unique-index value gap-locks under MySQL REPEATABLE READ, so garbage /
        // replayed tokens (the common abuse case) would serialize legitimate inserts.
        if (! $this->query()->where('token_hash', $hash)->exists()) {
            return null;
        }

        $row = $this->query()
            ->where('token_hash', $hash)
            ->lockForUpdate()
            ->first();

        return $row === null ? null : new RefreshTokenRecord(
            id: $row->id,
            userId: $row->user_id,
            familyId: $row->family_id,
            rotatedAt: $row->rotated_at?->getTimestamp(),
            revokedAt: $row->revoked_at?->getTimestamp(),
            expiresAt: $row->expires_at->getTimestamp(),
        );
    }

    public function persist(int|string $userId, string $familyId, ?string $previousId, string $tokenHash, int $expiresAt): void
    {
        $this->query()->create([
            'user_id' => $userId,
            'family_id' => $familyId,
            'previous_id' => $previousId,
            'token_hash' => $tokenHash,
            'expires_at' => $expiresAt, // Eloquent datetime cast accepts a unix timestamp
        ]);
    }

    public function markRotated(string $id): void
    {
        $this->query()->whereKey($id)->update(['rotated_at' => now()]);
    }

    public function revokeFamily(string $familyId): void
    {
        $this->query()
            ->where('family_id', $familyId)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);
    }

    public function revokeUserFamilies(int|string $userId): array
    {
        return $this->revokeActiveFamilies($userId, null);
    }

    public function revokeUserFamiliesExcept(int|string $userId, string $exceptFamilyId): array
    {
        return $this->revokeActiveFamilies($userId, $exceptFamilyId);
    }

    /**
     * @return array<int,string>
     */
    private function revokeActiveFamilies(int|string $userId, ?string $exceptFamilyId): array
    {
        $constrain = fn (Builder $query): Builder => $query
            ->where('user_id', $userId)
            ->when($exceptFamilyId !== null, fn (Builder $query) => $query->where('family_id', '!=', $exceptFamilyId))
            ->whereNull('revoked_at');

        // Atomic: a family created between the read and the update would otherwise
        // be revoked in the DB but never returned (so never denylisted).
        return DB::transaction(function () use ($constrain) {
            $ids = $constrain($this->query())->distinct()->pluck('family_id')->all();

            $constrain($this->query())->update(['revoked_at' => now()]);

            return $ids;
        });
    }

    public function pruneExpired(): int
    {
        // Two index-driven deletes rather than one `OR` scan (an OR across
        // expires_at + revoked_at can't use a single index).
        return $this->query()->where('expires_at', '<', now())->delete()
            + $this->query()->whereNotNull('revoked_at')->delete();
    }

    private function query(): Builder
    {
        $model = Lukk::refreshTokenModel();

        return $model::query();
    }
}
