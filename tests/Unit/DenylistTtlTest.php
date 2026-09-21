<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Lukk\Actions\Concerns\ComputesDenylistTtl;
use Lukk\Support\Abilities;
use Lukk\Support\VerifiedToken;
use Lukk\Tests\Fixtures\User;

function denylistTtl(array $config): int
{
    $subject = new class
    {
        use ComputesDenylistTtl;

        public function of(array $config): int
        {
            return $this->denylistTtl($config);
        }
    };

    return $subject->of($config);
}

it('outlives the last access token a revoked family can present', function (array $config, int $ttl) {
    expect(denylistTtl($config))->toBe($ttl);
})->with([
    'access_ttl + leeway' => [['access_ttl' => 300, 'leeway' => 10], 310],
    // Both unset add to 905, not 0: `Cache::put()` with a non-positive TTL forgets the key.
    'both unset' => [[], 905],
    'access_ttl unset' => [['leeway' => 10], 910],
    'leeway unset' => [['access_ttl' => 300], 305],
    'fractional strings from env' => [['access_ttl' => '300.5', 'leeway' => '10.5'], 310],
]);

it('covers a token that outlives the configured window, rather than under-covering it', function () {
    // `access_ttl` lowered between mint and revoke — cut from an hour to five minutes in response to
    // a suspected leak, then "log out everywhere" — used to write a 305s entry while the leaked
    // token stayed valid for another ~55 minutes, so it started working again mid-incident. A
    // rebound `TokenIssuer` does the same thing permanently: it owns `exp` and is told nothing about
    // `access_ttl`. The revoke now takes the longer of the two.
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;

    config(['lukk.access_ttl' => 300]);

    $request = Request::create('/auth/sessions', 'DELETE');
    $request->headers->set('Authorization', 'Bearer '.$access);
    $claims = verifier()->verify($access);
    VerifiedToken::put($request, new VerifiedToken(
        guard: 'api',
        userId: $user->getAuthIdentifier(),
        userClass: $user::class,
        familyId: (string) $claims->fid,
        abilities: Abilities::fromArray([]),
        claims: $claims,
    ));
    app()->instance('request', $request);

    // The token was minted under the default 900s TTL; the config now says 300.
    expect(denylistTtl(['access_ttl' => 300, 'leeway' => 5]))->toBeGreaterThan(305)
        ->and(denylistTtl(['access_ttl' => 300, 'leeway' => 5]))->toBeGreaterThanOrEqual(900);
});
