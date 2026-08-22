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
        /** @var Closure(): mixed $callback */
        return DB::transaction($callback);
    }

    public function findByHash(string $hash): ?RefreshTokenRecord
    {
        // `useWritePdo`, because this one runs OUTSIDE a transaction: `Connection::getReadPdo()`
        // returns the write PDO only while `transactions > 0`, so on a read/write split this read —
        // and only this read — lands on a replica, while the locked read inside the transaction
        // hits the primary. `sticky` doesn't help; a refresh has written nothing on the connection
        // yet. The row being looked up was inserted milliseconds ago by the previous rotation, which
        // is exactly the window replication lag covers, and a miss here would mint the successor
        // with no grant at all.
        return $this->hydrate($this->scoped()->useWritePdo()->where('token_hash', $hash)->first());
    }

    public function familyIsPinned(string $familyId): bool
    {
        // Reads the ROW and checks the attribute, rather than naming `scope` in a WHERE clause.
        //
        // Two traps avoided. Naming it fails differently per driver: on sqlite a double-quoted
        // identifier matching no column degrades to a STRING LITERAL, so `"scope" is not null` is
        // true for EVERY row — a pre-0.6 schema would have treated every token as a machine token
        // and 403'd logout-all for everybody. Guarding that with `Schema::hasColumn` then cost two
        // extra round trips, one of them `information_schema`, on every ordinary human request:
        // `pin` is present only on machine tokens, so this path is the common case, not the rare one.
        //
        // `select *` names no column, so a schema without `scope` simply yields no attribute.
        // Every row in a family carries the same value — written at insert, carried forward by
        // rotation, never updated — so one row answers for the family.
        // `orderBy` for determinism: every row in a family carries the same value today, but an
        // unordered `first()` would make the answer depend on storage order the moment one didn't.
        $row = $this->scoped()->useWritePdo()->where('family_id', $familyId)->orderBy('id')->first();

        return $row !== null && ($row->scope ?? null) !== null;
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

        return $this->hydrate($row);
    }

    private function hydrate(mixed $row): ?RefreshTokenRecord
    {
        return $row === null ? null : new RefreshTokenRecord(
            id: $row->id,
            userId: $row->user_id,
            familyId: $row->family_id,
            rotatedAt: $row->rotated_at?->getTimestamp(),
            revokedAt: $row->revoked_at?->getTimestamp(),
            expiresAt: $row->expires_at->getTimestamp(),
            scope: $row->scope ?? null,
            createdAt: $row->created_at?->getTimestamp(),
        );
    }

    public function persist(int|string $userId, string $familyId, ?string $previousId, string $tokenHash, int $expiresAt, ?string $scope = null): void
    {
        $attributes = [
            'user_id' => $userId,
            'family_id' => $familyId,
            'previous_id' => $previousId,
            'token_hash' => $tokenHash,
            'expires_at' => $expiresAt, // Eloquent datetime cast accepts a unix timestamp
        ];

        // Only when the family owns a grant — a null write would fail on a pre-0.6 schema that
        // hasn't published the new migration, and null is the default anyway.
        if ($scope !== null) {
            $attributes['scope'] = $scope;
        }

        // Only stamp the guard column under multi-guard; a single-guard schema has no such column.
        if ($this->guard !== null) {
            $attributes['guard'] = $this->guard;
        }

        // `forceFill`, not `create`: mass assignment respects the MODEL's `$fillable`/`$guarded`, and
        // `Lukk::useRefreshTokenModel()` is a documented seam. A subclass that declares `$fillable`
        // silently dropped `scope` — which turned a token pinned to `['ci.deploy']` into the
        // subject's full derived grant on its first refresh, and handed back session management with
        // it. Both halves of the defence collapsed together, because `familyIsPinned()` reads the
        // same column that was never written. These attributes are lukk's own; the consumer's
        // assignment policy has no business filtering them.
        $this->query()->newModelInstance()->forceFill($attributes)->save();
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

    public function deleteForUser(int|string $userId): int
    {
        // `scoped()`, like every other write on this class. It once wasn't, on the reasoning that "a
        // person asked to be forgotten once, not once per guard" — which assumes one `user_id` means
        // one person. Under multi-guard the providers are separate tables and `users.id ===
        // admins.id` is the norm, so the unscoped delete destroyed an unrelated admin's refresh
        // tokens: a permanent logout of a live account, with no `revoked_at` to explain it and no
        // denylist entry, because revocation IS scoped. An account is (guard, id), not id.
        return $this->scoped()->where('user_id', $userId)->delete();
    }

    public function allForUser(int|string $userId): array
    {
        // `hydrate()` is nullable only because it also serves the "row not found" reads; a row
        // that came back from `get()` always hydrates, and `array_values` keeps the list shape.
        return array_values(array_filter(
            $this->scoped()->where('user_id', $userId)->orderBy('created_at')
                ->get()->map(fn ($row) => $this->hydrate($row))->all()
        ));
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
    /** @return Builder<covariant \Lukk\Models\RefreshToken> */
    protected function query(): Builder
    {
        $model = Lukk::refreshTokenModel();

        return $model::query();
    }

    /** {@see query()} scoped to this repository's guard (no scope when guard is null). */
    /** @return Builder<covariant \Lukk\Models\RefreshToken> */
    private function scoped(): Builder
    {
        $query = $this->query();

        return $this->guard === null ? $query : $query->where('guard', $this->guard);
    }
}
