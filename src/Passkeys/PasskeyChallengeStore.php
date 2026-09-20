<?php

declare(strict_types=1);

namespace Lukk\Passkeys;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Str;
use Lukk\Lukk;

/**
 * Stateless WebAuthn challenge store. A JWT API has no session to hold the
 * single-use challenge, so it lives in the cache, short-TTL, read-and-delete (atomically — see
 * `redeem()`):
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
        return $this->redeem($this->userKey($userId));
    }

    public function putForCeremony(string $challenge): string
    {
        $ceremonyId = (string) Str::uuid();
        $this->cache->put($this->ceremonyKey($ceremonyId), $challenge, $this->ttl);

        return $ceremonyId;
    }

    public function pullForCeremony(string $ceremonyId): ?string
    {
        // A shortcut: no challenge is ever stored under an empty ceremony id.
        return $ceremonyId === '' ? null : $this->redeem($this->ceremonyKey($ceremonyId)); // @pest-mutate-ignore: EmptyStringToNotEmpty
    }

    /**
     * Read-and-delete, atomically: at most ONE caller ever gets a given challenge back.
     *
     * `Cache::pull()` is a get followed by a forget, so two requests presenting the same ceremony id
     * could both read the challenge before either deleted it, and both go on to verify an assertion
     * against it — the challenge was single-use only in the absence of concurrency.
     *
     * The claim is the same primitive the TOTP replay defence uses (`Google2FaTotpProvider`): `add()`
     * writes only when the key is absent and reports whether it did. Whoever wins the claim owns the
     * challenge; a loser gets null exactly as if the challenge had already been consumed.
     *
     * Atomic only where the STORE implements `add()` natively — Redis, Memcached, database, file,
     * DynamoDB. A store without it (APC, the memoizing decorator, array) makes the cache Repository
     * fall back to get-then-put, which reopens this race. The TOTP replay marker has the same limit,
     * and `CacheStoreGuard` deliberately refuses neither: APC is a legitimate single-host choice,
     * refusing it would also break the denylist on those installs, and such a rule belongs in that
     * shared guard rather than in one of its three users.
     *
     * The claim is keyed on the challenge VALUE, not on the storage key, because the registration key
     * is reused per user: keyed on it, a user retrying enrolment within the TTL would find every fresh
     * challenge already "claimed". A challenge is 128 random bits and never reissued. The marker
     * lives for the full TTL from the moment of the claim, which always outlasts the challenge it
     * guards (that was written earlier with the same TTL).
     */
    private function redeem(string $key): ?string
    {
        $challenge = $this->cache->get($key);

        if (! is_string($challenge)) {
            return null;
        }

        if (! $this->cache->add('lukk:pk:claimed:'.hash('sha256', $challenge), true, $this->ttl)) {
            return null;
        }

        $this->cache->forget($key);

        return $challenge;
    }

    /**
     * Guard-scoped: under multi-guard the providers are separate tables, so `users.id === admins.id`
     * is the ordinary case, and an unprefixed key let one account's in-flight registration overwrite
     * a colliding account's — the second ceremony then failed against the first's challenge. Read at
     * call time rather than injected, because this store is a singleton and the guard is per-request.
     */
    private function userKey(int|string $userId): string
    {
        return 'lukk:pk:reg:'.Lukk::currentGuard().":{$userId}";
    }

    private function ceremonyKey(string $ceremonyId): string
    {
        return "lukk:pk:login:{$ceremonyId}";
    }
}
