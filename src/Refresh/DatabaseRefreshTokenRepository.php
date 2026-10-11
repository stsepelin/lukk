<?php

declare(strict_types=1);

namespace Lukk\Refresh;

use Closure;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Lukk;
use Lukk\Support\RefreshTokenRecord;
use RuntimeException;

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
        return $this->connection()->transaction($callback);
    }

    /**
     * The connection the refresh-token model lives on. A transaction opened on the default one while the
     * queries run on a `useRefreshTokenModel` subclass's own connection guards nothing: the row lock is
     * taken in autocommit and released at once, so rotation and reuse detection stop being atomic.
     */
    private function connection(): ConnectionInterface
    {
        return $this->query()->getConnection();
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
        // No family of lukk's: see `isFamilyId()`.
        if (! self::isFamilyId($familyId)) {
            return false;
        }

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
        // Learn whether this schema carries `amr` from the ROW, the way `familyIsPinned()` reads the
        // row rather than naming `scope` — a SELECT * already tells us, so the answer is free. It
        // matters most on the rotation path, which always reads through the non-locking `findByHash`
        // BEFORE opening its transaction: the probe below would otherwise run under the row lock.
        if ($row !== null) {
            $this->rememberAmrSupport(array_key_exists('amr', $row->getAttributes()));
        }

        return $row === null ? null : new RefreshTokenRecord(
            id: $row->id,
            userId: $row->user_id,
            familyId: $row->family_id,
            rotatedAt: $row->rotated_at?->getTimestamp(),
            revokedAt: $row->revoked_at?->getTimestamp(),
            expiresAt: $row->expires_at->getTimestamp(),
            scope: $row->scope ?? null,
            // `?? null` because a pre-0.7 schema has no such column — the attribute is simply absent.
            amr: $row->amr ?? null,
            createdAt: $row->created_at?->getTimestamp(),
            // The family's original is the row `StartSession` inserted with no predecessor. Unlike
            // `scope`, this column needs no "is it there" guard: `persist()` writes `previous_id` on
            // every insert, so a schema lacking it could not have stored this row in the first place.
            original: $row->previous_id === null,
        );
    }

    public function persist(int|string $userId, string $familyId, ?string $previousId, string $tokenHash, int $expiresAt, ?string $scope = null, ?string $amr = null): void
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

        // `scope`'s "write it only when set" guard is NOT enough here. `scope` is non-null only for
        // an opt-in pinned grant, so on an un-migrated schema it almost never fires; every single
        // sign-in supplies an `amr`, so the same guard would name a missing column on every login —
        // and migrations here are publish-only, which makes that the DEFAULT outcome of upgrading
        // the package without republishing. So ask the schema, once per application instance.
        //
        // Proactively, not by catching the failure: `persist()` runs inside `RotateRefreshToken`'s
        // transaction, and on PostgreSQL a failed statement aborts it — every later statement then
        // errors with 25P02 and `COMMIT` silently becomes `ROLLBACK`. A try/catch here would turn a
        // missing column into a rotation that reports success and stores nothing.
        if ($amr !== null && $this->supportsAmr()) {
            $attributes['amr'] = $amr;
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
        //
        // QUIETLY, for the same reason: this runs inside `RotateRefreshToken`'s transaction, under the
        // parent row's lock, where no application code may run. `save()` fired the model's events, so an
        // observer on a `useRefreshTokenModel` subclass ran there — serialising the family's refreshes
        // behind it and, on PostgreSQL, turning a swallowed failing query into a COMMIT that silently
        // rolled back. And a `creating` listener returning false cancelled the write outright, so rotation
        // handed back a refresh token that was never stored. Audit sessions from lukk's events instead.
        //
        // A column the application must fill (a tenant trait's `tenant_id`, stamped from `creating`) is
        // therefore filled as the model is BUILT, not saved: `$attributes` defaults on the
        // `useRefreshTokenModel` subclass, or a trait's `initialize{Trait}()` method, which Eloquent runs
        // in the constructor with no event — or by overriding `persist()` in a subclass of this repository.
        // All of these still run under the lock, so they read values already in memory: no query.
        if (! $this->query()->newModelInstance()->forceFill($attributes)->saveQuietly()) {
            throw new RuntimeException('lukk could not store a refresh token: the refresh-token model\'s save() reported that nothing was written.');
        }
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
            // A Carbon, not a Unix integer: `expires_at` is a datetime column. The integer failed the whole
            // query on PostgreSQL (a 500 on every in-grace re-consumption, so the client's retry past grace
            // revoked the family), matched nothing on MySQL (the fork signal never fired), and matched
            // everything on sqlite. `pruneExpired()` compares the same way.
            ->where('expires_at', '>=', now())
            ->count();
    }

    public function revokeFamily(string $familyId): void
    {
        // Nothing to revoke in this table: see `isFamilyId()`. (The caller's denylist entry still lands.)
        if (! self::isFamilyId($familyId)) {
            return;
        }

        $revoke = fn (): int => $this->scoped()
            ->where('family_id', $familyId)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);

        $revoke();

        // Deliberately run TWICE. A rotation checks the denylist under its row lock, but a revoke
        // whose denylist write lands after that check and before the rotation commits is not seen
        // there. On PostgreSQL (READ COMMITTED) this UPDATE then takes its snapshot before the
        // successor row commits, blocks on the parent row the rotation holds, and on unblocking
        // re-checks ONLY that row — so the successor survives live, and rotates again once the
        // denylist entry expires. The second statement takes a fresh snapshot, which by then
        // includes the committed successor: the first UPDATE could only return after the rotation
        // released its lock, i.e. committed. InnoDB reads the latest version and needs no second
        // pass; it is a cheap no-op there. Pinned in tests/Concurrency.
        $revoke();
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
        // An "except" naming no family of lukk's spares nothing — every lukk family is an "other" one.
        if ($exceptFamilyId !== null && ! self::isFamilyId($exceptFamilyId)) {
            $exceptFamilyId = null;
        }

        $constrain = fn (Builder $query): Builder => $query
            ->where('user_id', $userId)
            ->when($exceptFamilyId !== null, fn (Builder $query) => $query->where('family_id', '!=', $exceptFamilyId))
            ->whereNull('revoked_at');

        // Every write below is limited to the family ids this SELECT read — the ids `$before` denylists and the
        // caller is handed back. The transaction does NOT keep the set still: PostgreSQL's READ COMMITTED gives
        // each statement a fresh snapshot, and InnoDB's UPDATE is a current read, so a session committed
        // between the SELECT and an UPDATE by the user's query is visible to it. Revoked that way, it was never
        // denylisted and never returned: signed out on its next refresh, with nothing recorded as to why.
        return $this->connection()->transaction(function () use ($constrain, $before) {
            $ids = $constrain($this->scoped())->distinct()->pluck('family_id')->all();

            // `$before` denylists, and it runs BEFORE the update and inside the transaction — the
            // same ordering `RevokeSession` documents and for the same reason. A leftover denylist
            // entry after a failed update is harmless and expires; rows revoked in the DB with no
            // denylist entry would keep authenticating for up to `access_ttl`, which is exactly the
            // window a user performing "log out everywhere" believes they have closed.
            if ($before !== null) {
                $before($ids);
            }

            if ($ids === []) {
                return [];
            }

            $revoke = fn (): int => $constrain($this->scoped())->whereIn('family_id', $ids)->update(['revoked_at' => now()]);

            // TWICE, for the reason `revokeFamily()` gives: on PostgreSQL the first UPDATE can block behind a
            // rotation of one of these families and, once unblocked, re-check only the row it waited on — the
            // successor that rotation committed is outside its snapshot. The second statement takes a fresh
            // one. A no-op on InnoDB. Pinned in tests/Concurrency.
            $revoke();
            $revoke();

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
        return array_values(array_filter( // @pest-mutate-ignore: UnwrapArrayFilter,UnwrapArrayValues
            $this->scoped()->where('user_id', $userId)->orderBy('created_at')
                ->get()->map(fn ($row) => $this->hydrate($row))->all()
        ));
    }

    public function pruneExpired(): int
    {
        // Only prune past `expires_at`. Keep revoked-but-unexpired rows so a replay of one still
        // resolves to `reuse` (fires the reuse event + family cascade) instead of a generic `unknown`
        // reject — they self-delete once they expire. Guard-agnostic: prunes every guard's expired rows.
        //
        // Nothing to prune where the publish-only migration never ran: the sweep is scheduled on every
        // install, a verify-only resource server included, and there it threw every day. Asked on the
        // model's own connection and table, as the passkey and lockout sweeps ask; not memoized, so a
        // worker started before the migration sees it once it has run.
        $query = $this->query();
        $model = $query->getModel();

        if (! Schema::connection($model->getConnectionName())->hasTable($model->getTable())) {
            return 0;
        }

        return $query->where('expires_at', '<', now())->delete();
    }

    /**
     * Whether a family id could name a row here: lukk mints every family as a UUID (`StartSession`).
     *
     * A co-issuer's `fid` need not be one — `42`, `"sess_42"` — and PostgreSQL types the parameter against
     * the native `uuid` column, so comparing one was SQLSTATE 22P02: a 500 on change-password, logout,
     * `DELETE /auth/sessions(/others)` and the pinned-ability gate on step-up confirmation, logout's
     * after the denylist write. Such an id names no family in this table, which is how it is answered.
     */
    private static function isFamilyId(string $familyId): bool
    {
        return Str::isUuid($familyId);
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

    /**
     * Does this install's `refresh_tokens` table carry the 0.7 `amr` column?
     *
     * Answered from a hydrated row wherever one has been read (free, and the rotation path always
     * reads one first), and only otherwise by asking the schema.
     *
     * Memoized per CONNECTION AND TABLE — and per database, `search_path` and prefix that connection
     * currently points at — on the application instance. Keying it globally answered
     * for the wrong schema the moment one application served two connections — a migrated tenant and
     * an un-migrated one — and the un-migrated INSERT then failed inside the rotate transaction,
     * which on PostgreSQL aborts it: every later statement errors `25P02` and `COMMIT` silently
     * becomes `ROLLBACK`. That is the precise failure this probe exists to avoid.
     *
     * On the application instance rather than in a `static`, because a process-static memo survives
     * between tests and between Octane requests and would answer for a schema that has since
     * migrated.
     */
    private function supportsAmr(): bool
    {
        $known = $this->rememberAmrSupport(null);

        if ($known !== null) {
            return $known;
        }

        $model = $this->query()->newModelInstance();

        try {
            // No `?? false`: `rememberAmrSupport()` returns null only when it was PASSED null, and
            // this passes a bool. The mutation run flagged the coalesce as unreachable, and the
            // repo's rule is to delete an equivalent rather than test it. The cast, likewise, only states
            // the type for the analyser: passed a bool, it returns that bool.
            return (bool) $this->rememberAmrSupport( // @pest-mutate-ignore: RemoveBooleanCast
                Schema::connection($model->getConnectionName())->hasColumn($model->getTable(), 'amr')
            );
        } catch (\Throwable) {
            // A transient probe failure — a blip, a deadlock, a statement timeout — must NOT be
            // cached: doing so disabled `amr` for the life of the application instance, silently.
            // Skipping the column for this one write is the safe direction; the next call re-asks.
            return false;
        }
    }

    /**
     * Read or record what we know about the `amr` column for THIS connection and table.
     *
     * Passing null reads; passing a bool records and returns it. Null back means "not yet known".
     */
    private function rememberAmrSupport(?bool $supported): ?bool
    {
        $model = $this->query()->newModelInstance();
        $connection = $model->getConnection();
        // What the connection points at NOW, not only its name: a tenancy package (stancl/tenancy) keeps
        // one name and switches the database — or, on PostgreSQL, the `search_path` — per tenant, and
        // a name-keyed answer then crossed tenants. JSON so no two parts can run together.
        $key = 'lukk.schema.amr.'.json_encode([
            $connection->getName(),
            $connection->getDatabaseName(),
            $connection->getConfig('search_path'),
            $connection->getTablePrefix(),
            $model->getTable(),
        ]);
        $app = app();

        if ($supported === null) {
            // The memo only ever stores a bool, so no cast: an equivalent mutant otherwise.
            return $app->bound($key) ? $app->make($key) : null;
        }

        $app->instance($key, $supported);

        return $supported;
    }
}
