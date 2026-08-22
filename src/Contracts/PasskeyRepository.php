<?php

declare(strict_types=1);

namespace Lukk\Contracts;

use Lukk\Support\NewPasskey;
use Lukk\Support\PasskeyRecord;

/**
 * Storage seam for passkey credentials. Default: the passkeys table.
 * Swap (DB, Redis, ...) without touching the ceremony or the actions.
 */
interface PasskeyRepository
{
    public function store(int|string $userId, NewPasskey $passkey, ?string $name = null): void;

    public function findByCredentialId(string $credentialId): ?PasskeyRecord;

    /**
     * Does ANY guard hold this credential id?
     *
     * Deliberately UNSCOPED, and the only method here that is. `credential_id` is globally unique —
     * WebAuthn requires it, and a credential belongs to exactly one account — so registration has to
     * ask a wider question than `findByCredentialId`, which is scoped precisely because it is the
     * assertion lookup. Without it a duplicate held by another guard reached the unique index and
     * surfaced as a 500 rather than a clean validation failure.
     */
    public function existsByCredentialId(string $credentialId): bool;

    /**
     * The user's credential ids (for excludeCredentials / allowCredentials).
     *
     * @return array<int,string>
     */
    public function credentialIdsFor(int|string $userId): array;

    public function updateSignCount(string $credentialId, int $signCount): void;

    /**
     * Lightweight metadata for listing a user's passkeys — no COSE key decryption.
     *
     * @return array<int,array{credential_id:string,name:?string,last_used_at:?int}>
     */
    public function summariesForUser(int|string $userId): array;

    public function delete(int|string $userId, string $credentialId): bool;

    /**
     * DELETE every passkey a user holds — erasure.
     *
     * A passkey row is squarely personal data: a credential id, the human-chosen device name
     * ("Yubikey at HQ"), and a last-used timestamp that describes the person's behaviour.
     *
     * @return int rows deleted
     */
    public function deleteForUser(int|string $userId): int;

    /**
     * DELETE passkeys whose user no longer exists.
     *
     * Nothing else ever removes these. A passkey has no expiry, so `lukk:prune` had nothing to do
     * with them, and erasure only reaches an account deleted through lukk's own route — a row
     * deleted directly, or by a cascade elsewhere, left the credential id, the human-chosen device
     * name and a last-used timestamp behind permanently.
     *
     * @return int rows deleted
     */
    public function pruneOrphaned(): int;
}
