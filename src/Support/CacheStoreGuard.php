<?php

declare(strict_types=1);

namespace Lukk\Support;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\NullStore;
use Illuminate\Contracts\Cache\Repository;
use RuntimeException;

/**
 * Refuse a cache store that cannot hold a revocation.
 *
 * Everything that makes an ALREADY-ISSUED credential stop working lives in this cache: the
 * denylist, the TOTP replay marker, the passkey challenge. An `array` store is per-process, so a
 * revoked token stays valid on every other worker and the single-use guarantees are not guarantees
 * at all — and it fails silently, which is the part that makes it dangerous. `null` discards every
 * write, so it fails the same way but completely.
 *
 * Only in production: the array driver is the right default for a test suite, and lukk's own suite
 * runs on it.
 */
class CacheStoreGuard
{
    public static function assertCanHoldRevocations(Repository $store): void
    {
        if (! app()->environment('production')) {
            return;
        }

        $driver = $store->getStore();

        if ($driver instanceof ArrayStore || $driver instanceof NullStore) {
            throw new RuntimeException(
                'lukk cannot use the ['.class_basename($driver).'] cache store: token revocation, '
                .'two-factor replay protection and passkey challenges all live there, and it keeps '
                .'nothing another process can see. Point LUKK_DENYLIST_STORE at a shared, persistent '
                .'store (Redis) — and never one your deploy flushes, since `cache:clear` would '
                .'resurrect every token revoked in the last access_ttl.'
            );
        }
    }
}
