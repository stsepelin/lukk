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
 * Default storage: the refresh_tokens table via Eloquent. The model is resolved through
 * Lukk::refreshTokenModel() so apps can swap it.
 *
 * Multi-guard: constructed with a `$guard` name, every read/write is scoped by the `guard` column
 * so one guard's families are invisible to another even when user ids collide (users.id ==
 * admins.id). A `null` guard (the single-guard default) applies no scope and touches no `guard`
 * column — identical to the pre-multi-guard behavior and schema.
 */
class DatabaseRefreshTokenRepository implements RefreshTokenRepository
{
    public function __construct(private readonly ?string $guard = null) {}

    public function transaction(Closure $callback): mixed
    {
        return DB::transaction($callback);
    }

    public function findByHashForUpdate(string $hash): ?RefreshTokenRecord
    {
        // Non-locking existence check first: `FOR UPDATE` on an absent unique value gap-locks under MySQL REPEATABLE READ.
        if (! $this->scoped()->where('token_hash', $hash)->exists()) {
            return null;
        }

        $row = $this->scoped()
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
        $attributes = [
            'user_id' => $userId,
            'family_id' => $familyId,
            'previous_id' => $previousId,
            'token_hash' => $tokenHash,
            'expires_at' => $expiresAt, // Eloquent datetime cast accepts a unix timestamp
        ];

        // Only stamp the guard column under multi-guard; a single-guard schema has no such column.
        if ($this->guard !== null) {
            $attributes['guard'] = $this->guard;
        }

        $this->query()->create($attributes);
    }

    public function markRotated(string $id): void
    {
        $this->scoped()->whereKey($id)->update(['rotated_at' => now()]);
    }

    public function countLiveTokens(string $familyId): int
    {
        return $this->scoped()
            ->where('family_id', $familyId)
            ->whereNull('rotated_at')
            ->whereNull('revoked_at')
            ->where('expires_at', '>=', now()->getTimestamp())
            ->count();
    }

    public function revokeFamily(string $familyId): void
    {
        $this->scoped()
            ->where('family_id', $familyId)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);
    }

    public function revokeUserFamilies(int|string $userId, ?callable $before = null): array
    {
        return $this->revokeActiveFamilies($userId, null, $before);
    }

    public function revokeUserFamiliesExcept(int|string $userId, string $exceptFamilyId, ?callable $before = null): array
    {
        return $this->revokeActiveFamilies($userId, $exceptFamilyId, $before);
    }

    /**
     * @return array<int,string>
     */
    private function revokeActiveFamilies(int|string $userId, ?string $exceptFamilyId, ?callable $before = null): array
    {
        $constrain = fn (Builder $query): Builder => $query
            ->where('user_id', $userId)
            ->when($exceptFamilyId !== null, fn (Builder $query) => $query->where('family_id', '!=', $exceptFamilyId))
            ->whereNull('revoked_at');

        // Atomic: a family created between the read and update would be revoked but never returned (so never denylisted).
        return DB::transaction(function () use ($constrain, $before) {
            $ids = $constrain($this->scoped())->distinct()->pluck('family_id')->all();

            // `$before` denylists, and it runs BEFORE the update and inside the transaction — the
            // same ordering `RevokeSession` documents and for the same reason. A leftover denylist
            // entry after a failed update is harmless and expires; rows revoked in the DB with no
            // denylist entry would keep authenticating for up to `access_ttl`, which is exactly the
            // window a user performing "log out everywhere" believes they have closed.
            if ($before !== null) {
                $before($ids);
            }

            $constrain($this->scoped())->update(['revoked_at' => now()]);

            return $ids;
        });
    }

    public function pruneExpired(): int
    {
        // Only prune past `expires_at`. Keep revoked-but-unexpired rows so a replay of one still
        // resolves to `reuse` (fires the reuse event + family cascade) instead of a generic `unknown`
        // reject — they self-delete once they expire. Guard-agnostic: prunes every guard's expired rows.
        return $this->query()->where('expires_at', '<', now())->delete();
    }

    /**
     * The base query on the configured refresh-token model. Protected so a consumer can subclass
     * with a different model/table without re-implementing the repository.
     */
    protected function query(): Builder
    {
        $model = Lukk::refreshTokenModel();

        return $model::query();
    }

    /** {@see query()} scoped to this repository's guard (no scope when guard is null). */
    private function scoped(): Builder
    {
        $query = $this->query();

        return $this->guard === null ? $query : $query->where('guard', $this->guard);
    }
}
