<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Cache\ArrayStore;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Exceptions;
use Lukk\Actions\Concerns\ComputesDenylistTtl;
use Lukk\Actions\RevokeSession;
use Lukk\Actions\StartSession;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Support\Abilities;
use Lukk\Support\LongestAccessTtl;
use Lukk\Support\VerifiedToken;
use Lukk\Tests\Fixtures\LocklessStore;
use Lukk\Tests\Fixtures\User;

function denylistTtl(array $config): int
{
    $subject = new class
    {
        use ComputesDenylistTtl;

        public function of(array $config): int
        {
            return $this->denylistTtl($config, 'api');
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
    $this->freezeSecond();
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

    expect(LongestAccessTtl::current('api'))->toBe(0)
        ->and(denylistTtl(['access_ttl' => 60, 'leeway' => 5]))->toBeGreaterThanOrEqual(3600)->toBeLessThanOrEqual(3605);
});

it('reads the recorded lifetime as an integer, whatever the store hands back', function () {
    // Redis returns what it stores as a string.
    cache()->store()->put('lukk:access-ttls:api', ['1800'], 60);
    cache()->store()->put('lukk:access-ttl:api:1800', true, 60);

    expect(LongestAccessTtl::current('api'))->toBe(1800);
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

    expect(LongestAccessTtl::current('api'))->toBe(1800);
});

it('uses the configured window when no request is bound at all, as in a queued job', function () {
    app()->offsetUnset('request');

    expect(denylistTtl(['access_ttl' => 60, 'leeway' => 5]))->toBe(65);
});

it('records no lifetime that is not positive', function () {
    LongestAccessTtl::record(0, 'api');
    LongestAccessTtl::record(-5, 'api');

    expect(LongestAccessTtl::current('api'))->toBe(0);
});

it('keeps each guard\'s record apart, and reads the one the revoke was built for', function () {
    // A revoke resolved under one guard and run under another (a queued job) read the AMBIENT guard's
    // record and denylisted for its shorter window, so the other guard's long token verified again.
    LongestAccessTtl::record(3600, 'admin');

    expect(LongestAccessTtl::current('admin'))->toBe(3600)
        ->and(LongestAccessTtl::current('api'))->toBe(0);

    app()->instance(Denylist::class, $spy = new class implements Denylist
    {
        public array $ttls = [];

        public function revokeJti(string $jti, int $ttlSeconds): void {}

        public function revokeFamily(string $familyId, int $ttlSeconds): void
        {
            $this->ttls[] = $ttlSeconds;
        }

        public function has(string $type, string $id): bool
        {
            return false;
        }

        public function hasAny(array $types): bool
        {
            return false;
        }
    });
    $revoke = new RevokeSession(app(RefreshTokenRepository::class), $spy, ['access_ttl' => 300, 'leeway' => 5], 'admin');

    $revoke('fam');

    expect($spy->ttls)->toBe([3605]);
});

it('remembers a longer lifetime minted alongside a shorter one, whichever is recorded last', function () {
    // The old record kept one shared maximum, read and then written: a concurrent shorter mint could
    // overwrite a longer one. Each lifetime now has its own key.
    LongestAccessTtl::record(3600, 'api');
    LongestAccessTtl::record(300, 'api');

    expect(LongestAccessTtl::current('api'))->toBe(3600);

    $this->travel(3601)->seconds();
    LongestAccessTtl::record(300, 'api');

    expect(LongestAccessTtl::current('api'))->toBe(300);
});

it('reads the longest minted lifetime from the configured denylist store, not the default one', function () {
    config(['cache.stores.lukk-deny' => ['driver' => 'array']]);
    LongestAccessTtl::record(3600, 'api', 'lukk-deny');

    expect(denylistTtl(['access_ttl' => 300, 'leeway' => 5, 'denylist_store' => 'lukk-deny']))->toBe(3605);
});

it('records lifetimes in a store that cannot lock', function () {
    // The index write is serialised under a lock only where the store offers one.
    $store = new LocklessStore;
    Cache::extend('lockless', fn () => Cache::repository($store));
    config(['cache.stores.lukk-lockless' => ['driver' => 'lockless']]);

    LongestAccessTtl::record(1800, 'api', 'lukk-lockless');

    expect(LongestAccessTtl::current('api', 'lukk-lockless'))->toBe(1800);
});

/** A denylist store that reads but refuses every write, as a full or failing cache does. */
function unwritableDenylistStore(): void
{
    Cache::extend('unwritable', fn () => Cache::repository(new class extends ArrayStore
    {
        public function put($key, $value, $seconds): bool
        {
            throw new RuntimeException('cache is down');
        }

        public function forever($key, $value): bool
        {
            throw new RuntimeException('cache is down');
        }
    }));
    config(['cache.stores.lukk-unwritable' => ['driver' => 'unwritable'], 'lukk.denylist_store' => 'lukk-unwritable']);
}

it('does not let a failure to record the lifetime cost a committed rotation its answer', function () {
    // Recorded after the commit. A throw there left the successor committed and the parent consumed while
    // the client got a 500 — and its retry past the grace window is indistinguishable from a replay, so
    // reuse detection revoked the whole family. The record is advisory: reported, never fatal.
    $pair = start()(1);
    unwritableDenylistStore();
    Exceptions::fake();

    $next = rotate()($pair->refreshToken);

    Exceptions::assertReported(fn (RuntimeException $e) => $e->getMessage() === 'cache is down');
    expect(rotate()($next->refreshToken)->refreshToken)->toBeString();
});

it('does not let a failure to record the lifetime fail a sign-in whose session already exists', function () {
    unwritableDenylistStore();
    Exceptions::fake();

    $pair = start()(1);

    Exceptions::assertReported(fn (RuntimeException $e) => $e->getMessage() === 'cache is down');
    expect($pair->refreshToken)->toBeString();
});

it('still records a new lifetime when the index lock cannot be had in time', function () {
    // The lock only serialises the index write. Waiting it out and THROWING made a busy store fail the
    // mint; the unlocked add can at worst lose a concurrent value, which the next mint of it restores.
    Cache::extend('contended', fn () => Cache::repository(new class extends ArrayStore
    {
        public function lock($name, $seconds = 0, $owner = null)
        {
            return new class(parent::lock($name, $seconds, $owner)) implements Lock
            {
                public function __construct(private readonly Lock $inner) {}

                public function get($callback = null)
                {
                    return false;
                }

                public function block($seconds, $callback = null)
                {
                    throw new LockTimeoutException;
                }

                public function release()
                {
                    return $this->inner->release();
                }

                public function owner()
                {
                    return $this->inner->owner();
                }

                public function forceRelease()
                {
                    $this->inner->forceRelease();
                }
            };
        }
    }));
    config(['cache.stores.lukk-contended' => ['driver' => 'contended']]);
    Exceptions::fake();

    LongestAccessTtl::record(1800, 'api', 'lukk-contended');

    expect(LongestAccessTtl::current('api', 'lukk-contended'))->toBe(1800);
    Exceptions::assertNothingReported();
});

it('clamps the leeway it adds exactly as the verifier clamps the one it allows', function (mixed $leeway, int $ttl) {
    // The verifier reads `Lukk::leeway()`, 0..300. A raw negative leeway here SHORTENED the entry below
    // the token's real life, so a revoked family's access token verified again for its last minutes.
    expect(denylistTtl(['access_ttl' => 300, 'leeway' => $leeway]))->toBe($ttl);
})->with([
    'negative' => [-120, 300],
    'past the cap' => [86_400, 600],
]);

it('keeps a revoked family denylisted to the end of its access token under a negative leeway', function () {
    config(['lukk.access_ttl' => 300, 'lukk.leeway' => -120]);
    $pair = start()(1);
    $familyId = verifier()->verify($pair->accessToken)->fid;

    revokeSession()($familyId);
    // The token is accepted until `exp` (the verifier floors the leeway at 0); 280 s in, it has 20 left.
    $this->travel(280)->seconds();

    expect(app(Denylist::class)->has('fid', $familyId))->toBeTrue();
});

it('keeps a co-issued token denylisted to its end at logout under a negative leeway', function () {
    config(['lukk.leeway' => -120]);
    $cfg = Lukk\Lukk::guardConfig();
    $token = JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => '1', 'jti' => 'co-issued',
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);

    $this->withToken($token)->postJson('/auth/logout')->assertNoContent();
    $this->travel(580)->seconds();

    expect(app(Denylist::class)->has('jti', 'co-issued'))->toBeTrue();
});

it('writes nothing for a lifetime that is not positive, not even to the index', function () {
    LongestAccessTtl::record(0, 'api');
    LongestAccessTtl::record(-5, 'api');

    expect(Cache::get('lukk:access-ttls:api'))->toBeNull();
});

it('touches the index only when a lifetime is new to it', function () {
    // Every mint records; rewriting the index each time would take the lock on every sign-in and refresh.
    $store = new class extends LocklessStore
    {
        public int $indexWrites = 0;

        public function forever($key, $value): bool
        {
            $this->indexWrites++;

            return parent::forever($key, $value);
        }
    };
    Cache::extend('counting', fn () => Cache::repository($store));
    config(['cache.stores.lukk-counting' => ['driver' => 'counting']]);

    LongestAccessTtl::record(900, 'api', 'lukk-counting');
    LongestAccessTtl::record(900, 'api', 'lukk-counting');
    LongestAccessTtl::record(300, 'api', 'lukk-counting');

    expect($store->indexWrites)->toBe(2);
});
