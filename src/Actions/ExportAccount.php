<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Carbon;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\RefreshTokenRepository;

/**
 * Gather the personal data lukk holds about a user (GDPR Art. 15 / Art. 20).
 *
 * **This is the AUTH slice only.** lukk knows about sessions, passkeys and whether two-factor is on;
 * it knows nothing about the data a subject actually cares about. An application serving this as
 * its complete Art. 15 response would be under-disclosing — the controller's docblock and the docs
 * both say so, because a half-answer that looks whole is worse than no endpoint.
 *
 * **Credential material is deliberately excluded.** A TOTP secret, recovery codes and refresh-token
 * hashes are not "personal data the subject is entitled to receive" in any useful sense — they are
 * secrets whose only use is authenticating as them. Art. 15(4) says the right of access must not
 * adversely affect others, and handing a live second-factor secret to whoever intercepts an export
 * is exactly that. What is included is the FACT of a credential (this passkey exists, it was last
 * used then), which is the part that describes the person.
 */
class ExportAccount
{
    public function __construct(
        private readonly RefreshTokenRepository $tokens,
        private readonly PasskeyRepository $passkeys,
        private readonly string $identifierColumn,
        // Optional only so a direct construction written against 0.6 keeps working; the provider
        // always supplies both, and without them the export simply has no lockout section to fill.
        private readonly ?LockoutRepository $lockouts = null,
        private readonly ?string $guard = null,
    ) {}

    /** A unix timestamp as ISO-8601 — the shape `RefreshTokenRecord` stores its times in. */
    private function fromTimestamp(?int $timestamp): ?string
    {
        return $timestamp === null ? null : Carbon::createFromTimestamp($timestamp)->toIso8601String();
    }

    /**
     * A timestamp as ISO-8601, whatever shape the model hands over.
     *
     * `two_factor_confirmed_at` is a column on the CONSUMER's users table, and whether it is cast to
     * a date is their decision, not lukk's — an uncast model yields a raw string. Assuming Carbon
     * here turned a data-subject export into a 500.
     */
    private function iso(mixed $value): ?string
    {
        if ($value instanceof \DateTimeInterface) {
            return $value->format(\DateTimeInterface::ATOM);
        }

        return is_string($value) && $value !== '' ? Carbon::parse($value)->toIso8601String() : null;
    }

    /** The value the account authenticates with, as a string — see `DeleteAccount::identifierOf()`. */
    private function identifierOf(Authenticatable $user): ?string
    {
        $value = $user->{$this->identifierColumn} ?? null;

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * @return array<string, mixed>
     */
    public function __invoke(Authenticatable $user): array
    {
        $userId = $user->getAuthIdentifier();

        return [
            'generated_at' => now()->toIso8601String(),
            'account' => [
                'id' => $userId,
                // Normalized the same way `DeleteAccount::identifierOf()` does. A consumer's column
                // may be cast (a Carbon, a BackedEnum), and one side emitting an object where the
                // other emits a string is how the two drift.
                'identifier' => $this->identifierOf($user),
            ],
            // Metadata only: no token, no hash. `family_id` is the session's stable identity across
            // rotations, which is what makes the list meaningful to a person reading it.
            // Through the REPOSITORY, which is guard-scoped — reading the model directly returned
            // every row sharing this `user_id`, and under multi-guard the providers are separate
            // tables where `users.id === admins.id` is the norm. One subject was handed another's
            // session history under Art. 15, which Art. 15(4) explicitly forbids. It also bypassed
            // the documented DB↔Redis swap seam, so a swapped install exported nothing at all.
            'sessions' => array_map(fn ($record) => [
                'session' => $record->familyId,
                'created_at' => $this->fromTimestamp($record->createdAt),
                'last_rotated_at' => $this->fromTimestamp($record->rotatedAt),
                'revoked_at' => $this->fromTimestamp($record->revokedAt),
                'expires_at' => $this->fromTimestamp($record->expiresAt),
            ], $this->tokens->allForUser($userId)),
            // The FACT of each passkey, never the COSE public key: the key identifies the
            // authenticator, not the person, and publishing it helps nobody read their own data.
            // See `passkeySummary()` for what is carried, and why through an allowlist.
            //
            // Guarded on the TABLE, not on the feature flag — the same rule as `DeleteAccount`, and
            // for the mirror-image reason. A feature switched off after use leaves its rows behind,
            // and injecting null when the flag is off made the export silently omit passkeys that
            // still exist: under-disclosure under Art. 15 of exactly the rows erasure would destroy.
            // An install that never published the migration has no table, which the database store
            // answers itself, so a rebound store that is not that table is exported too.
            'passkeys' => array_map(fn (array $passkey) => $this->passkeySummary($passkey), $this->passkeys->summariesForUser($userId)),
            'two_factor' => [
                'enabled' => method_exists($user, 'hasEnabledTwoFactor') && $user->hasEnabledTwoFactor(),
                'confirmed_at' => $this->iso($user->two_factor_confirmed_at ?? null),
            ],
            'lockouts' => $this->lockoutsFor($user),
        ];
    }

    /**
     * One passkey as the export states it: every field erasure destroys that describes the person —
     * when it was added and last used, what it is called, the authenticator model (AAGUID) and how it
     * connects — so Art. 15 discloses what Art. 17 deletes. Times in ISO-8601, like the rest of the file.
     *
     * Mapped through this allowlist, and typed, rather than passed through: the summary comes from a
     * swap seam, and a rebound store returning its whole row would otherwise publish the public key.
     *
     * @param  array<string, mixed>  $passkey
     * @return array<string, mixed>
     */
    private function passkeySummary(array $passkey): array
    {
        $transports = $passkey['transports'] ?? null;

        return [
            'credential_id' => (string) $passkey['credential_id'],
            'name' => is_string($passkey['name'] ?? null) ? $passkey['name'] : null,
            'created_at' => is_int($passkey['created_at'] ?? null) ? $this->fromTimestamp($passkey['created_at']) : null,
            'last_used_at' => is_int($passkey['last_used_at'] ?? null) ? $this->fromTimestamp($passkey['last_used_at']) : null,
            'aaguid' => is_string($passkey['aaguid'] ?? null) ? $passkey['aaguid'] : null,
            'transports' => is_array($transports) ? array_values(array_filter($transports, 'is_string')) : null,
        ];
    }

    /**
     * The consecutive-failure counters held against this account — the rows `DeleteAccount` erases,
     * reached through the same three key spaces, so an access request discloses everything erasure
     * would destroy.
     *
     * The purpose and counts, never the subject key: `id:`/`idn:` is lukk's storage format, not
     * information about the person. Guarded on the table, not the feature flag, for the same reason
     * as passkeys above — a switched-off feature leaves its rows behind.
     *
     * @return array<int, array<string, mixed>>
     */
    private function lockoutsFor(Authenticatable $user): array
    {
        // An unpublished table is the database store's to answer, so a rebound store is exported too.
        if ($this->lockouts === null) {
            return [];
        }

        $identifier = $this->identifierOf($user);

        $rows = $this->lockouts->summariesForSubjects([
            // id:<userId> — login. (The identifier argument is unused when a user is passed.)
            LoginRateLimiter::lockoutSubject($user, ''), // @pest-mutate-ignore: EmptyStringToNotEmpty
            (string) $user->getAuthIdentifier(),                                                // <userId>      — confirm / two-factor
            $identifier === null ? '' : LoginRateLimiter::lockoutSubject(null, $identifier),    // idn:sha256:<digest>
            $identifier === null ? '' : LoginRateLimiter::legacyLockoutSubject($identifier), // idn:<normalized>, written before 0.7
        ], $this->guard);

        return array_map(fn (array $row) => [
            'purpose' => $row['purpose'],
            'attempts' => $row['attempts'],
            'locked_at' => $this->fromTimestamp($row['locked_at']),
            'first_failed_at' => $this->fromTimestamp($row['first_failed_at']),
            'last_failed_at' => $this->fromTimestamp($row['last_failed_at']),
        ], $rows);
    }
}
