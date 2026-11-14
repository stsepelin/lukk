<?php

declare(strict_types=1);

use Illuminate\Cache\ArrayStore;
use Illuminate\Support\Facades\Cache;
use Lukk\Support\CacheDenylist;

it('asks the store nothing when there is no token id to look up', function () {
    // An empty MGET is an error on Redis; the array store the suite runs on would not notice.
    $store = new class extends ArrayStore
    {
        public int $manyCalls = 0;

        public function many(array $keys)
        {
            $this->manyCalls++;

            if ($keys === []) {
                throw new LogicException('MGET with no keys');
            }

            return parent::many($keys);
        }
    };
    Cache::extend('strict-many', fn () => Cache::repository($store));
    config(['cache.stores.strict' => ['driver' => 'strict-many']]);

    expect((new CacheDenylist(['denylist_store' => 'strict']))->hasAny(['family' => '', 'jti' => '']))->toBeFalse()
        // Not asked at all: an empty id is not a key, so there is nothing to look up.
        ->and($store->manyCalls)->toBe(0);
});

it('reads any stored marker as denylisted, whatever the store hands back', function () {
    // A store that returns 1 rather than true still means "revoked"; `has()` answers a bool either way.
    $store = Cache::store('array');
    $store->put('lukk:dl:jti:abc', 1, 60);

    expect((new CacheDenylist(['denylist_store' => 'array']))->has('jti', 'abc'))->toBeTrue();
});

it('keeps its markers in the configured store, not the default one', function () {
    // The default cache is routinely a per-server `file` or `array` store; revocations have to be where
    // every worker can see them.
    config(['cache.stores.shared' => ['driver' => 'array']]);

    (new CacheDenylist(['denylist_store' => 'shared']))->revokeJti('jti-1', 60);

    expect((new CacheDenylist(['denylist_store' => 'shared']))->has('jti', 'jti-1'))->toBeTrue()
        ->and((new CacheDenylist([]))->has('jti', 'jti-1'))->toBeFalse();
});
