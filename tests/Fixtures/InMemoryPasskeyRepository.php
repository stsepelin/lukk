<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Lukk\Contracts\PasskeyRepository;
use Lukk\Support\NewPasskey;
use Lukk\Support\PasskeyRecord;

/**
 * A passkey store that is not the database: what a consumer rebinding the contract (Redis, another
 * service) looks like to lukk. There is no `passkeys` table behind it, so anything lukk gates on that
 * table silently skips this store.
 */
class InMemoryPasskeyRepository implements PasskeyRepository
{
    /** @var array<string, array{user: int|string, sign_count: int}> */
    public array $rows = [];

    public function store(int|string $userId, NewPasskey $passkey, ?string $name = null): void
    {
        $this->rows[$passkey->credentialId] = ['user' => $userId, 'sign_count' => $passkey->signCount];
    }

    public function findByCredentialId(string $credentialId): ?PasskeyRecord
    {
        return null;
    }

    public function existsByCredentialId(string $credentialId): bool
    {
        return isset($this->rows[$credentialId]);
    }

    public function credentialIdsFor(int|string $userId): array
    {
        return array_keys(array_filter($this->rows, fn (array $row): bool => $row['user'] == $userId));
    }

    public function updateSignCount(string $credentialId, int $signCount): bool
    {
        return false;
    }

    public function summariesForUser(int|string $userId): array
    {
        return array_map(fn (string $id): array => [
            'credential_id' => $id, 'name' => null, 'last_used_at' => null,
        ], $this->credentialIdsFor($userId));
    }

    public function delete(int|string $userId, string $credentialId): bool
    {
        if (! in_array($credentialId, $this->credentialIdsFor($userId), true)) {
            return false;
        }

        unset($this->rows[$credentialId]);

        return true;
    }

    public function deleteForUser(int|string $userId): int
    {
        $ids = $this->credentialIdsFor($userId);
        foreach ($ids as $id) {
            unset($this->rows[$id]);
        }

        return count($ids);
    }

    public function pruneOrphaned(): int
    {
        return 0;
    }
}
