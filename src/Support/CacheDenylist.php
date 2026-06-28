<?php

declare(strict_types=1);

namespace Lukk\Support;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Lukk\Contracts\Denylist as DenylistContract;

/**
 * Cache-backed denylist. Entries self-evict at access_ttl, so size is
 * O(recently-revoked sessions), not O(issued tokens). Revoke by `fid` to kill
 * a whole session in one entry, or by `jti` for a single access token.
 */
class CacheDenylist implements DenylistContract
{
    private readonly Repository $store;

    /**
     * @param  array{denylist_store:?string,...}  $config
     */
    public function __construct(array $config)
    {
        $this->store = Cache::store($config['denylist_store'] ?? null);
    }

    public function revokeJti(string $jti, int $ttlSeconds): void
    {
        $this->store->put($this->key('jti', $jti), true, $ttlSeconds);
    }

    public function revokeFamily(string $familyId, int $ttlSeconds): void
    {
        $this->store->put($this->key('fid', $familyId), true, $ttlSeconds);
    }

    public function has(string $type, string $id): bool
    {
        return $id !== '' && (bool) $this->store->get($this->key($type, $id));
    }

    public function hasAny(array $types): bool
    {
        $keys = [];

        foreach ($types as $type => $id) {
            if ($id !== '') {
                $keys[] = $this->key($type, (string) $id);
            }
        }

        if ($keys === []) {
            return false;
        }

        foreach ($this->store->many($keys) as $value) {
            if ($value) {
                return true;
            }
        }

        return false;
    }

    private function key(string $type, string $id): string
    {
        return "lukk:dl:{$type}:{$id}";
    }
}
