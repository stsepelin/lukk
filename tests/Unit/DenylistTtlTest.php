<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Lukk\Actions\Concerns\ComputesDenylistTtl;
use Lukk\Actions\RevokeSession;
use Lukk\Actions\StartSession;
use Lukk\Support\Abilities;
use Lukk\Support\LongestAccessTtl;
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

it('adds leeway to the presented token\'s own remaining life', function () {
    // Without it the entry expires exactly when the token does, while the verifier still accepts
    // that token for `leeway` seconds past `exp` — a window in which a revoked family authenticates
    // again. The configured floor already carries leeway, so only the presented-token branch can
    // lose it; this pins that branch on its own by keeping the floor far below it.
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;

    $request = Request::create('/auth/sessions', 'DELETE');
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

    $remaining = (int) $claims->exp - now()->getTimestamp();

    expect(denylistTtl(['access_ttl' => 1, 'leeway' => 30]))->toBe($remaining + 30);
});

it('keeps a family revoked for as long as its longest token lives, after access_ttl is lowered', function () {
    // A revoke denylisted for the CONFIGURED `access_ttl + leeway`. Lowered from 3600 to 60 during an
    // incident, a family revoked afterwards — logout, reuse, "everywhere" — had its entry expire after
    // 65 s, and its hour-long access token verified again (RFC 7009 §2.2). Revocation now covers the
    // longest access token this deployment has minted while one can still be alive. Revoked from the
    // console here, so no presented token can supply the answer instead.
    config(['lukk.access_ttl' => 3600]);
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    $fid = (string) verifier()->verify($access)->fid;

    config(['lukk.access_ttl' => 60]);
    app(RevokeSession::class)($fid);

    $this->travel(120)->seconds();

    expect(verifier()->verify($access))->toBeNull();
});

it('forgets the longest lifetime once no token minted under it can be alive', function () {
    config(['lukk.access_ttl' => 3600]);
    User::factory()->create()->startSession();
    config(['lukk.access_ttl' => 60]);

    expect(denylistTtl(['access_ttl' => 60, 'leeway' => 5]))->toBe(3605);

    $this->travel(3601)->seconds();

    expect(denylistTtl(['access_ttl' => 60, 'leeway' => 5]))->toBe(65);
});

it('caps the clock-skew leeway at a few minutes', function () {
    // RFC 7519 §4.1.4 allows "some small leeway". `LUKK_LEEWAY=86400` stretched every exp by a day.
    config(['lukk.leeway' => 86400]);
    $expired = $this->travel(-1)->hours(fn () => issuer()->accessToken(ctx('1'))['token']);

    expect(verifier()->verify($expired))->toBeNull();
});

it('covers a presented token lukk never recorded minting, such as a co-issuer\'s', function () {
    // The longest-lifetime record only knows tokens THIS deployment minted through its own actions. A
    // token minted elsewhere — a co-issuer sharing the key, or the issuer called directly — is covered by
    // the lifetime it presents.
    config(['lukk.access_ttl' => 3600]);
    $token = issuer()->accessToken(ctx('1'))['token'];
    config(['lukk.access_ttl' => 60]);

    $request = Request::create('/auth/sessions', 'DELETE');
    $claims = verifier()->verify($token);
    VerifiedToken::put($request, new VerifiedToken(guard: 'api', userId: '1', userClass: User::class, familyId: 'fam', abilities: Abilities::fromArray([]), claims: $claims));
    app()->instance('request', $request);

    expect(LongestAccessTtl::current())->toBe(0)
        ->and(denylistTtl(['access_ttl' => 60, 'leeway' => 5]))->toBeGreaterThanOrEqual(3600)->toBeLessThanOrEqual(3605);
});

it('reads the recorded lifetime as an integer, whatever the store hands back', function () {
    // Redis returns what it stores as a string.
    cache()->store()->put('lukk:longest-access-ttl:api', '1800', 60);

    expect(LongestAccessTtl::current())->toBe(1800);
});

it('decodes a stored amr up to its cap, and a list as a list', function () {
    expect(StartSession::decodeAmr('["pwd","otp","mfa"]'))->toBe(['pwd', 'otp', 'mfa'])
        ->and(StartSession::decodeAmr(str_pad('["pwd"]', StartSession::MAX_AMR_LENGTH, ' ')))->toBe(['pwd'])
        ->and(StartSession::decodeAmr(str_pad('["pwd"]', StartSession::MAX_AMR_LENGTH + 1, ' ')))->toBeNull();
});

it('adds the configured leeway to a presented token\'s remaining life, five seconds when unset', function () {
    $this->freezeSecond();
    config(['lukk.access_ttl' => 3600]);
    $token = issuer()->accessToken(ctx('1'))['token'];
    $request = Request::create('/auth/sessions', 'DELETE');
    VerifiedToken::put($request, new VerifiedToken(guard: 'api', userId: '1', userClass: User::class, familyId: 'fam', abilities: Abilities::fromArray([]), claims: verifier()->verify($token)));
    app()->instance('request', $request);

    expect(denylistTtl(['access_ttl' => 60]))->toBe(3605)
        ->and(denylistTtl(['access_ttl' => 60, 'leeway' => 9]))->toBe(3609);
});

it('falls back to the configured window when the request presents no token', function () {
    app()->instance('request', Request::create('/'));

    expect(denylistTtl(['access_ttl' => 60, 'leeway' => 5]))->toBe(65);
});

it('records the lifetime a rotation mints, as a sign-in does', function () {
    config(['lukk.access_ttl' => 60]);
    $pair = start()(1);
    config(['lukk.access_ttl' => 1800]);

    rotate()($pair->refreshToken);

    expect(LongestAccessTtl::current())->toBe(1800);
});
