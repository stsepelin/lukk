<?php

declare(strict_types=1);

namespace Lukk\Passkeys;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Schema;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Lukk;
use Lukk\Models\Passkey;
use Lukk\Support\NewPasskey;
use Lukk\Support\PasskeyRecord;

/**
 * Default storage: the passkeys table. The COSE public key is
 * encrypted at rest; the credential id is the primary key (globally unique).
 */
class DatabasePasskeyRepository implements PasskeyRepository
{
    public function __construct(private readonly ?string $guard = null) {}

    public function store(int|string $userId, NewPasskey $passkey, ?string $name = null): void
    {
        $attributes = [
            'credential_id' => $passkey->credentialId,
            'user_id' => $userId,
            'name' => $name,
            'public_key' => Crypt::encryptString($passkey->publicKey),
            'sign_count' => $passkey->signCount,
            'transports' => $passkey->transports,
            'aaguid' => $passkey->aaguid,
        ];

        // Only stamp the column under multi-guard; a single-guard schema may not have it yet, and a
        // null guard means exactly what it meant before the column existed.
        if ($this->guard !== null) {
            $attributes['guard'] = $this->guard;
        }

        Passkey::query()->create($attributes);
    }

    public function findByCredentialId(string $credentialId): ?PasskeyRecord
    {
        // SCOPED, and this is the important one: a WebAuthn assertion arrives with a credential id
        // and no user, so this lookup is what decides who just authenticated. Unscoped, an admin's
        // credential resolved on the users guard.
        $row = $this->scoped()->find($credentialId);

        return $row === null ? null : $this->toRecord($row);
    }

    public function existsByCredentialId(string $credentialId): bool
    {
        // NOT `scoped()`: the unique index this backstops is global, so the question is too.
        return Passkey::query()->whereKey($credentialId)->exists();
    }

    public function credentialIdsFor(int|string $userId): array
    {
        return $this->scoped()->where('user_id', $userId)->pluck('credential_id')->all();
    }

    public function updateSignCount(string $credentialId, int $signCount): void
    {
        $this->scoped()->whereKey($credentialId)->update([
            'sign_count' => $signCount,
            'last_used_at' => now(),
        ]);
    }

    public function summariesForUser(int|string $userId): array
    {
        return $this->scoped()->where('user_id', $userId)
            ->get(['credential_id', 'name', 'last_used_at'])
            ->map(fn (Passkey $row) => [
                'credential_id' => $row->credential_id,
                'name' => $row->name,
                'last_used_at' => $row->last_used_at?->getTimestamp(),
            ])->all();
    }

    public function delete(int|string $userId, string $credentialId): bool
    {
        return (bool) $this->scoped()->where('user_id', $userId)->whereKey($credentialId)->delete();
    }

    private function toRecord(Passkey $row): PasskeyRecord
    {
        return new PasskeyRecord(
            credentialId: $row->credential_id,
            userId: $row->user_id,
            publicKey: Crypt::decryptString($row->public_key),
            signCount: (int) $row->sign_count,
            transports: $row->transports ?? [],
            aaguid: $row->aaguid,
            name: $row->name,
            lastUsedAt: $row->last_used_at?->getTimestamp(),
        );
    }

    public function deleteForUser(int|string $userId): int
    {
        return $this->scoped()->where('user_id', $userId)->delete();
    }

    public function pruneOrphaned(): int
    {
        // Passkeys are an opt-in feature with a publish-only migration, so most installs have no
        // such table. `lukk:prune` is SCHEDULED DAILY by default — throwing here broke the scheduled
        // prune for every install that never enabled passkeys, taking the refresh-token and lockout
        // sweeps down with it.
        if (! Schema::hasTable((new Passkey)->getTable())) {
            return 0;
        }

        // The `guard` column went into the EXISTING `create_passkeys_table` migration, so every
        // install that already ran it has no such column until they act on UPGRADE.md — and unlike
        // the request paths (which under a single guard apply no scope and never name the column),
        // this sweep names it either way. Naming it on a pre-0.6 schema fails in two different
        // directions: MySQL/PostgreSQL throw `Unknown column`, and since `lukk:prune` is `->daily()`
        // that takes the refresh-token and lockout sweeps down with it every night; SQLite instead
        // degrades a double-quoted identifier matching no column to a STRING LITERAL, so
        // `"guard" is null` is false for every row and the sweep silently deletes nothing, forever,
        // while reporting success. That is the same SQLite trap already pinned for `scope`.
        //
        // Two round trips are affordable HERE, unlike on the `pin` path, because this is a
        // console-only command that runs once a day rather than on every ordinary request.
        $scopable = Schema::hasColumn((new Passkey)->getTable(), 'guard');

        // A GLOBAL sweep. It runs from the console, where `$this->guard` is whatever `GuardContext`
        // happens to hold — never null, since it falls back to the default guard — which is
        // meaningless for a command that must cover every guard. So it ignores the instance scope
        // and enumerates them itself.
        //
        // Each guard is swept against ITS OWN provider table. Deciding orphanhood against a single
        // table — as this once did — makes every other provider's credential orphaned by
        // construction, and this command runs daily, so it silently deleted a live admin's second
        // factor over and over. A row lukk cannot attribute (a `guard` that predates the column, or
        // names a guard since removed) is LEFT ALONE: retention is the safe direction for a sweep
        // whose failure mode is destroying a credential someone still uses.
        $deleted = 0;

        foreach ($this->guardProviders($scopable) as $guard => $provider) {
            $model = config("auth.providers.{$provider}.model");

            // A non-Eloquent provider has no table to compare against. Skip that guard rather than
            // guess — deleting on a failed lookup would erase every passkey it owns.
            if (! is_string($model) || ! class_exists($model)) {
                continue;
            }

            /** @var Model $user */
            $user = new $model;

            // A subquery cannot cross connections. If the provider's table lives on another one, the
            // bare table name resolves against the PASSKEYS connection — which either throws
            // (`no such table`, aborting every guard still queued behind it) or, worse, silently
            // matches a same-named table there and reads every real credential as orphaned. Skip:
            // the same "rather than guess" rule as the non-Eloquent case above.
            if ($user->getConnection()->getName() !== (new Passkey)->getConnection()->getName()) {
                continue;
            }

            $deleted += Passkey::query()
                ->when($scopable, fn ($q) => $q->when(
                    $guard !== '',
                    fn ($inner) => $inner->where('guard', $guard),
                    fn ($inner) => $inner->whereNull('guard'),
                ))
                // A soft-deleted user is still a row, and is deliberately NOT orphaned: keeping the
                // row is a retention decision the application made, and their passkeys go with it.
                ->whereNotIn('user_id', fn ($sub) => $sub->select($user->getKeyName())->from($user->getTable()))
                ->delete();
        }

        return $deleted;
    }

    /**
     * Every guard lukk authenticates, mapped to the auth provider whose table backs it.
     *
     * Keyed by the value stored in the `guard` COLUMN, so `''` means the null column that a
     * single-guard install (and any row predating the column) carries.
     *
     * Providers resolve as `LukkServiceProvider::userProviderFor()` does: the default guard from
     * `lukk.user_provider`, an extra guard from its own `config/auth.php` provider. Reading
     * `lukk.user_provider` for every guard would resolve them all to the SAME table, which is the
     * bug this method exists to avoid wearing a different hat.
     *
     * @param  bool  $scopable  Whether the `guard` column exists.
     * @return array<string, string>
     */
    private function guardProviders(bool $scopable = true): array
    {
        $fallback = (string) (config('lukk.user_provider') ?? 'users');

        // No column on a MULTI-GUARD install: sweep NOTHING. Treating it as single-guard would run
        // one unscoped pass against only the DEFAULT provider's table, which reads every other
        // guard's credential as orphaned — precisely the bug the column exists to fix, reintroduced
        // in the pre-column path, on a daily irreversible command. Such an install is mid-upgrade
        // and has not run the ALTER yet; the same "skip rather than guess" rule as the non-Eloquent
        // and cross-connection cases applies.
        if (! $scopable) {
            return Lukk::isMultiGuard() ? [] : ['' => $fallback];
        }

        if (! Lukk::isMultiGuard()) {
            return ['' => $fallback];
        }

        // Under multi-guard the default guard stamps its own name, so nothing legitimate carries a
        // null `guard` — anything that does predates the column and is not ours to delete.
        $providers = [(string) config('lukk.guard', 'api') => $fallback];

        foreach (array_keys((array) config('lukk.guards', [])) as $name) {
            $providers[(string) $name] ??= (string) (config("auth.guards.{$name}.provider") ?? $fallback);
        }

        return $providers;
    }

    /**
     * Deliberately asymmetric, matching `DatabaseRefreshTokenRepository::scoped()`.
     *
     * A null guard (single-guard, and every row written before the column existed) applies NO
     * filter, which is what makes the column back-compatible. The consequence is that removing a
     * guard from `lukk.guards` leaves its stamped rows visible to the default guard — and here that
     * is an authentication decision, not just a data-tidiness one. Scoping single-guard reads to
     * `whereNull('guard')` instead would fix that and break the far more common upgrade path, where
     * the column does not exist yet at all. It is a documented cleanup step in UPGRADE.md.
     */
    /** @return Builder<covariant Passkey> */
    private function scoped(): Builder
    {
        $query = Passkey::query();

        return $this->guard === null ? $query : $query->where('guard', $this->guard);
    }
}
