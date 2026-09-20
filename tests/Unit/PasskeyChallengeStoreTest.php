<?php

declare(strict_types=1);

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Lukk\Passkeys\PasskeyChallengeStore;

uses()->group('passkeys');

function challengeStore(): PasskeyChallengeStore
{
    return app(PasskeyChallengeStore::class);
}

it('generates a base64url challenge of at least 16 bytes', function () {
    $challenge = challengeStore()->generate();

    expect($challenge)->toBeString();
    expect(strlen((string) base64_decode(strtr($challenge, '-_', '+/'))))->toBeGreaterThanOrEqual(16);
});

it('stores and pulls a user registration challenge once (single-use)', function () {
    challengeStore()->putForUser(7, 'CHALLENGE');

    expect(challengeStore()->pullForUser(7))->toBe('CHALLENGE');
    expect(challengeStore()->pullForUser(7))->toBeNull();
});

it('stores a login challenge under an opaque ceremony id (single-use)', function () {
    $id = challengeStore()->putForCeremony('CHALLENGE');

    expect($id)->toBeString()->not->toBe('');
    expect(challengeStore()->pullForCeremony($id))->toBe('CHALLENGE');
    expect(challengeStore()->pullForCeremony($id))->toBeNull();
});

it('returns null pulling an empty or unknown ceremony id', function () {
    expect(challengeStore()->pullForCeremony(''))->toBeNull();
    expect(challengeStore()->pullForCeremony('unknown'))->toBeNull();
});

/**
 * A cache that lets a second, "concurrent" redemption run at the worst moment: right after the first
 * one has READ the challenge and before it has done anything else. That is the interleaving a
 * get-then-forget `pull()` loses, and the one an atomic claim must win.
 */
function racingCache(Closure $concurrent): Repository
{
    return new class(new ArrayStore, $concurrent) extends Repository
    {
        private bool $armed = true;

        public mixed $concurrentResult = null;

        public function __construct(ArrayStore $store, private readonly Closure $concurrent)
        {
            parent::__construct($store);
        }

        public function get($key, $default = null): mixed
        {
            $value = parent::get($key, $default);

            if ($this->armed && is_string($key) && str_starts_with($key, 'lukk:pk:') && $value !== null) {
                $this->armed = false;
                $this->concurrentResult = ($this->concurrent)();
            }

            return $value;
        }
    };
}

it('redeems a login challenge at most once when two requests race', function () {
    // `Cache::pull()` is get-then-forget: two requests presenting the same ceremony id can both read
    // the challenge before either deletes it, and both go on to verify an assertion against it.
    $store = null;
    $ceremony = '';
    $cache = racingCache(function () use (&$store, &$ceremony) {
        return $store->pullForCeremony($ceremony);
    });
    $store = new PasskeyChallengeStore($cache, 120);
    $ceremony = $store->putForCeremony('CHALLENGE');

    $first = $store->pullForCeremony($ceremony);
    $results = array_values(array_filter([$first, $cache->concurrentResult]));

    // Exactly one winner — and it got the real challenge.
    expect($results)->toBe(['CHALLENGE']);
});

it('redeems a registration challenge at most once when two requests race', function () {
    $store = null;
    $cache = racingCache(function () use (&$store) {
        return $store->pullForUser(7);
    });
    $store = new PasskeyChallengeStore($cache, 120);
    $store->putForUser(7, 'CHALLENGE');

    $first = $store->pullForUser(7);

    expect(array_filter([$first, $cache->concurrentResult]))->toHaveCount(1);
});

it('lets the same user start a fresh registration ceremony straight after redeeming one', function () {
    // The claim marker must be tied to the CHALLENGE, not to the user key — otherwise a user who
    // retries registration within the challenge lifetime would find every new challenge "claimed".
    challengeStore()->putForUser(8, 'FIRST');
    expect(challengeStore()->pullForUser(8))->toBe('FIRST');

    challengeStore()->putForUser(8, 'SECOND');
    expect(challengeStore()->pullForUser(8))->toBe('SECOND')
        ->and(challengeStore()->pullForUser(8))->toBeNull();
});
