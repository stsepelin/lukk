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
}
