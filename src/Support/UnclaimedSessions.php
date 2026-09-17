<?php

declare(strict_types=1);

namespace Lukk\Support;

use Illuminate\Contracts\Cache\Repository;

/**
 * The cache markers behind `claim_seconds`: one entry per session family that has been issued but not
 * yet used, holding its issue time.
 *
 * Lives in the revocation cache store (`denylist_store`), which `CacheStoreGuard` already requires to
 * be shared and persistent. A MISSING marker means "claimed" — whether it was claimed, never marked, or
 * evicted by the cache. That fails OPEN on purpose: failing closed would log out every session whose
 * marker a cache flush or memory pressure dropped, and an evicted marker costs only the cleanup this
 * feature adds, never a security property lukk otherwise has.
 */
class UnclaimedSessions
{
    public function __construct(private readonly Repository $store) {}

    /**
     * The EFFECTIVE claim window for a guard's resolved config, in seconds; 0 means the feature is off.
     *
     * Read defensively: no config key is guaranteed under a cached config, and a non-numeric value
     * must switch the feature OFF rather than cast to a window that would revoke every session.
     *
     * Clamped to at least `access_ttl + leeway`, and to at least 60 seconds. What the clamp guarantees
     * is narrow: the sign-in's original ACCESS token can never be used past the window, because it has
     * expired by then — so only its original refresh token can arrive late. It does NOT protect a client
     * that never touches this app within the window. `access_ttl + leeway` is exactly when a resource
     * server stops accepting the original token, so a client using the token only on another service,
     * and refreshing after that service's 401, arrives just past the window and is revoked. Such a
     * client must call `POST {path}/session/claim`. Widening the window further would only move the
     * boundary, not remove it.
     *
     * @param  array<string, mixed>  $config
     */
    public static function window(array $config): int
    {
        $window = $config['claim_seconds'] ?? null;

        if (! is_numeric($window) || (int) $window <= 0) {
            return 0;
        }

        $accessTtl = is_numeric($config['access_ttl'] ?? null) ? (int) $config['access_ttl'] : 900;
        $leeway = is_numeric($config['leeway'] ?? null) ? (int) $config['leeway'] : 0;

        return max((int) $window, $accessTtl + $leeway, 60);
    }

    /**
     * Mark a newly issued family. The TTL covers the family's whole refresh lifetime, so the marker
     * cannot expire by TTL while a first use could still arrive and matter.
     */
    public function mark(string $familyId, int $ttlSeconds): void
    {
        $this->store->put($this->key($familyId), now()->getTimestamp(), max(1, $ttlSeconds));
    }

    /** When the family was issued, or null when it carries no marker — claimed, never marked, or evicted. */
    public function issuedAt(string $familyId): ?int
    {
        $issuedAt = $this->store->get($this->key($familyId));

        return is_numeric($issuedAt) ? (int) $issuedAt : null;
    }

    public function forget(string $familyId): void
    {
        $this->store->forget($this->key($familyId));
    }

    private function key(string $familyId): string
    {
        return 'lukk:unclaimed:'.$familyId;
    }
}
