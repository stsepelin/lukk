<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Lukk\Support\UnclaimedSessions;

it('clamps the claim window to the access token lifetime plus leeway, and to a minute', function (array $config, int $window) {
    expect(UnclaimedSessions::window($config))->toBe($window);
})->with([
    'a window above the clamp is kept' => [['claim_seconds' => 1000, 'access_ttl' => 100, 'leeway' => 10], 1000],
    'clamped to access_ttl + leeway' => [['claim_seconds' => 70, 'access_ttl' => 100, 'leeway' => 10], 110],
    'clamped to a minute' => [['claim_seconds' => 10, 'access_ttl' => 20, 'leeway' => 5], 60],
    'access_ttl unset: 900' => [['claim_seconds' => 10, 'leeway' => 10], 910],
    'leeway unset: 5, what the verifier reads' => [['claim_seconds' => 10, 'access_ttl' => 100], 105],
    'unusable values read as unset' => [['claim_seconds' => 10, 'access_ttl' => 'abc', 'leeway' => 'abc'], 905],
    // Fractional strings from env: each cast keeps the method's int return type.
    'a fractional window' => [['claim_seconds' => '1000.5', 'access_ttl' => 100, 'leeway' => 5], 1000],
    'a fractional access_ttl' => [['claim_seconds' => 10, 'access_ttl' => '100.7', 'leeway' => 5], 105],
    'a fractional leeway' => [['claim_seconds' => 10, 'access_ttl' => 100, 'leeway' => '5.5'], 105],
    'off when unset' => [[], 0],
    'off when zero' => [['claim_seconds' => '0'], 0],
    'off when not a number' => [['claim_seconds' => 'soon'], 0],
]);

it('keeps a marker for at least a second, even with no refresh lifetime left', function () {
    // `put()` with a TTL of 0 FORGETS the key: the session would count as claimed from birth.
    $this->freezeSecond();
    $sessions = new UnclaimedSessions(Cache::store('array'));

    $sessions->mark('fam', 0);
    expect($sessions->issuedAt('fam'))->toBe(now()->getTimestamp());

    $this->travel(1)->seconds();
    expect($sessions->issuedAt('fam'))->toBeNull();
});

it('reads a marker a cache store hands back as a string', function () {
    // Redis and the database store return what they stored as a string.
    $store = Cache::store('array');
    $store->put('lukk:unclaimed:fam', '1700000000', 60);

    expect((new UnclaimedSessions($store))->issuedAt('fam'))->toBe(1700000000);
});
