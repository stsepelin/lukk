<?php

declare(strict_types=1);

use Illuminate\Cache\ArrayLock;
use Illuminate\Cache\ArrayStore;
use Illuminate\Support\Facades\Cache;
use Lukk\Support\LongestAccessTtl;

/*
 * The index of access-token lifetimes a guard has minted. What it is FOR is pinned in DenylistTtlTest;
 * this is the bookkeeping that file cannot see from the outside: what the index holds after a write, and
 * that the write is serialised where the store can serialise it.
 */

it('records a lifetime of one second', function () {
    // The floor is "not positive", not "not above one".
    LongestAccessTtl::record(1, 'api');

    expect(LongestAccessTtl::current('api'))->toBe(1);
});

it('rewrites the index as integers, dropping what is not a number', function () {
    // What Redis hands back, with an entry somebody edited by hand: left in, the junk came back as a
    // lifetime of 0 and the strings never compared equal to the integer being recorded.
    cache()->store()->forever('lukk:access-ttls:api', [3 => '900', 7 => 'junk']);

    LongestAccessTtl::record(60, 'api');

    expect(cache()->store()->get('lukk:access-ttls:api'))->toBe([900, 60]);
});

it('does not write the index again for a lifetime it already lists', function () {
    LongestAccessTtl::record(900, 'api');
    cache()->store()->forever('lukk:access-ttls:api', [900, 'left alone']);

    LongestAccessTtl::record(900, 'api');

    expect(cache()->store()->get('lukk:access-ttls:api'))->toBe([900, 'left alone']);
});

it('adds to the index under a lock of its own, held and waited for five seconds', function () {
    // Two mints of two NEW lifetimes at once each read the index, append, and write: unserialised, one
    // of them is lost, and the denylist TTL then undershoots a token that is still alive.
    $store = new class extends ArrayStore
    {
        /** @var list<array{string, int}> */
        public array $locked = [];

        /** @var list<int> */
        public array $waited = [];

        public function lock($name, $seconds = 0, $owner = null)
        {
            $this->locked[] = [$name, $seconds];
            $recorder = $this;

            return new class($this, $name, $seconds, $owner, $recorder) extends ArrayLock
            {
                public function __construct($store, $name, $seconds, $owner, private readonly object $recorder)
                {
                    parent::__construct($store, $name, $seconds, $owner);
                }

                public function block($seconds, $callback = null)
                {
                    $this->recorder->waited[] = $seconds;

                    return parent::block($seconds, $callback);
                }
            };
        }
    };
    Cache::extend('recording', fn () => Cache::repository($store));
    config(['cache.stores.recording' => ['driver' => 'recording']]);

    LongestAccessTtl::record(900, 'api', 'recording');

    expect($store->locked)->toBe([['lukk:access-ttls:api:lock', 5]])
        ->and($store->waited)->toBe([5])
        ->and(LongestAccessTtl::current('api', 'recording'))->toBe(900);
});
