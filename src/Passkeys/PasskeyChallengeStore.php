<?php

declare(strict_types=1);

namespace Lukk\Passkeys;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Str;

/**
 * Stateless WebAuthn challenge store. A JWT API has no session to hold the
 * single-use challenge, so it lives in the cache, short-TTL, read-and-delete:
 *  - registration: keyed by the authenticated user.
 *  - login: keyed by an opaque ceremony id (no identity yet), returned to the
 *    client and echoed back. The challenge itself is never sent to the client.
 */
class PasskeyChallengeStore
{
    public function __construct(
        private readonly Repository $cache,
        private readonly int $ttl,
    ) {}

    public function generate(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
    }

    public function putForUser(int|string $userId, string $challenge): void
    {
        $this->cache->put($this->userKey($userId), $challenge, $this->ttl);
    }

    public function pullForUser(int|string $userId): ?string
    {
        return $this->cache->pull($this->userKey($userId));
    }

    public function putForCeremony(string $challenge): string
    {
        $ceremonyId = (string) Str::uuid();
        $this->cache->put($this->ceremonyKey($ceremonyId), $challenge, $this->ttl);

        return $ceremonyId;
    }

    public function pullForCeremony(string $ceremonyId): ?string
    {
        return $ceremonyId === '' ? null : $this->cache->pull($this->ceremonyKey($ceremonyId));
    }

    private function userKey(int|string $userId): string
    {
        return "lukk:pk:reg:{$userId}";
    }

    private function ceremonyKey(string $ceremonyId): string
    {
        return "lukk:pk:login:{$ceremonyId}";
    }
}
