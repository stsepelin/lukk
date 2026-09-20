<?php

declare(strict_types=1);

use Illuminate\Cache\ArrayStore;
use Illuminate\Support\Facades\Cache;
use Lukk\Support\CacheDenylist;

it('asks the store nothing when there is no token id to look up', function () {
    // An empty MGET is an error on Redis; the array store the suite runs on would not notice.
    Cache::extend('strict-many', fn () => Cache::repository(new class extends ArrayStore
    {
        public function many(array $keys)
        {
            if ($keys === []) {
                throw new LogicException('MGET with no keys');
            }

            return parent::many($keys);
        }
    }));
    config(['cache.stores.strict' => ['driver' => 'strict-many']]);

    expect((new CacheDenylist(['denylist_store' => 'strict']))->hasAny(['family' => '', 'jti' => '']))->toBeFalse();
});
