<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Schema;
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

    /**
     * Whether a table is there to read.
     *
     * Deliberately NOT memoized, and the same spelling as `DeleteAccount` — a static cache is
     * answered once per PROCESS, so a worker started before a migration keeps saying "no such
     * table" for its whole life.
     */
    private function tableExists(string $table): bool
    {
        return Schema::hasTable($table);
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
            //
            // Guarded on the TABLE, not on the feature flag — the same rule as `DeleteAccount`, and
            // for the mirror-image reason. A feature switched off after use leaves its rows behind,
            // and injecting null when the flag is off made the export silently omit passkeys that
            // still exist: under-disclosure under Art. 15 of exactly the rows erasure would destroy.
            // An install that never published the migration has no table, and that is the only case
            // worth skipping.
            'passkeys' => $this->tableExists('passkeys') ? $this->passkeys->summariesForUser($userId) : [],
            'two_factor' => [
                'enabled' => method_exists($user, 'hasEnabledTwoFactor') && $user->hasEnabledTwoFactor(),
                'confirmed_at' => $this->iso($user->two_factor_confirmed_at ?? null),
            ],
        ];
    }
}
