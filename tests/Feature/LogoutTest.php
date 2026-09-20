<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Support\Facades\Event;
use Lukk\Actions\EndSession;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\LogoutResponse;
use Lukk\Events\RefreshTokenReused;
use Lukk\Lukk;
use Lukk\Models\RefreshToken;
use Lukk\Support\TokenPair;
use Lukk\Tests\Fixtures\User;

// `POST /auth/logout` ends the session with EITHER credential the client holds: a valid access token,
// or the refresh token. It used to sit behind `auth:{guard}`, so a client whose access token had
// expired — the ordinary state of an idle tab — got a 401, nothing was revoked, and in cookie mode the
// `__Host-refresh` cookie stayed valid for its whole TTL (RFC 7009 §2.1–2.2, ASVS 5.0 V7.4.1).
uses()->group('refresh');

// Integer-second grace comparisons, as in RotateRefreshTokenTest.
beforeEach(fn () => $this->freezeSecond());

/** A session whose ACCESS token has already expired — minted at a travelled clock, verified at the real one. */
function expiredSession(User $user): TokenPair
{
    return test()->travel(-3600)->seconds(fn () => $user->startSession());
}

function familyOf(string $refreshToken): string
{
    return (string) RefreshToken::where('token_hash', hash('sha256', $refreshToken))->value('family_id');
}

function familyIsLive(string $familyId): bool
{
    return RefreshToken::where('family_id', $familyId)->whereNull('revoked_at')->exists();
}

function routeFor(string $method, string $uri): RoutingRoute
{
    return collect(app('router')->getRoutes())
        ->firstOrFail(fn ($route) => $route->uri() === $uri && in_array($method, $route->methods(), true));
}

it('revokes the family of a valid bearer, as before', function () {
    $pair = User::factory()->create()->startSession();
    $fid = familyOf($pair->refreshToken);

    $this->withToken($pair->accessToken)->postJson('/auth/logout')->assertNoContent();

    expect(familyIsLive($fid))->toBeFalse()
        ->and(app(Denylist::class)->has('fid', $fid))->toBeTrue();
});

it('denylists the jti of a valid bearer that carries no family', function () {
    // A co-issuer sharing the secret mints tokens with no `fid`. There is no family to revoke, but the
    // token itself must stop working here — before, logout did nothing at all for it.
    $cfg = Lukk::guardConfig();
    $token = JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => '1', 'jti' => 'co-issued',
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);

    expect(verifier()->verify($token))->not->toBeNull();

    $this->withToken($token)->postJson('/auth/logout')->assertNoContent();

    expect(app(Denylist::class)->has('jti', 'co-issued'))->toBeTrue()
        ->and(verifier()->verify($token))->toBeNull();
});

it('ends a cookie-mode session with an expired access token, using the refresh cookie', function () {
    config(['lukk.cookie_mode' => true]);
    $pair = expiredSession(User::factory()->create());
    $fid = familyOf($pair->refreshToken);

    expect(verifier()->verify($pair->accessToken))->toBeNull();   // genuinely expired

    $response = $this->withToken($pair->accessToken)
        ->withCredentials()->withUnencryptedCookie('__Host-refresh', $pair->refreshToken)
        ->postJson('/auth/logout')
        ->assertNoContent();

    // The family is gone server-side...
    expect(familyIsLive($fid))->toBeFalse()
        ->and(app(Denylist::class)->has('fid', $fid))->toBeTrue();

    // ...the browser is told to drop the cookie...
    $cleared = collect($response->headers->getCookies())->firstOrFail(fn ($c) => $c->getName() === '__Host-refresh');
    expect((string) $cleared->getValue())->toBe('')
        ->and($cleared->getExpiresTime())->toBeLessThan(time());

    // ...and a copy of the cookie kept by anyone else no longer refreshes.
    $this->withCredentials()->withUnencryptedCookie('__Host-refresh', $pair->refreshToken)->postJson('/auth/refresh')->assertUnauthorized();
});

it('ends a body-mode session with an expired access token, using the refresh_token field', function () {
    $pair = expiredSession(User::factory()->create());
    $fid = familyOf($pair->refreshToken);

    $this->withToken($pair->accessToken)
        ->postJson('/auth/logout', ['refresh_token' => $pair->refreshToken])
        ->assertNoContent();

    expect(familyIsLive($fid))->toBeFalse();
    $this->postJson('/auth/refresh', ['refresh_token' => $pair->refreshToken])->assertUnauthorized();
});

it('does not take an expired access token as authority on its own', function () {
    // A correctly signed but EXPIRED token proves only that it was once issued. Honouring it would turn
    // every access token that ever leaked into a log into a 30-day capability to end that session.
    $pair = expiredSession(User::factory()->create());
    $fid = familyOf($pair->refreshToken);

    $this->withToken($pair->accessToken)->postJson('/auth/logout')->assertNoContent();

    expect(familyIsLive($fid))->toBeTrue()
        ->and(app(Denylist::class)->has('fid', $fid))->toBeFalse();
});

it('answers 204 with no credentials at all, revokes nothing, and is idempotent', function () {
    $pair = User::factory()->create()->startSession();
    $fid = familyOf($pair->refreshToken);

    $this->postJson('/auth/logout')->assertNoContent();
    $this->postJson('/auth/logout')->assertNoContent();
    $this->withToken('not.a.jwt')->postJson('/auth/logout', ['refresh_token' => 'not-a-real-token'])->assertNoContent();

    expect(familyIsLive($fid))->toBeTrue();
});

it('answers identically whether or not the refresh token exists', function () {
    // Never an oracle for "that token was real". Same status, same (empty) body, same cookies.
    config(['lukk.cookie_mode' => true]);
    $pair = User::factory()->create()->startSession();

    $real = $this->withCredentials()->withUnencryptedCookie('__Host-refresh', $pair->refreshToken)->postJson('/auth/logout');
    $fake = $this->withCredentials()->withUnencryptedCookie('__Host-refresh', 'not-a-real-token')->postJson('/auth/logout');

    // The real one really did something, so the comparison below is not two no-ops agreeing.
    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse()
        ->and($real->getStatusCode())->toBe(204);

    expect($real->getStatusCode())->toBe($fake->getStatusCode())
        ->and($real->getContent())->toBe($fake->getContent())
        ->and(array_map(fn ($c) => [$c->getName(), $c->getValue()], $real->headers->getCookies()))
        ->toBe(array_map(fn ($c) => [$c->getName(), $c->getValue()], $fake->headers->getCookies()));
});

it('revokes both families when the bearer and the refresh token name different sessions', function () {
    // A browser can hold an access token from one login and a cookie from a later one. "Log me out"
    // means both; neither credential grants anything the other did not already allow, since either
    // alone can end its own session.
    $user = User::factory()->create();
    $first = $user->startSession();
    $second = $user->startSession();

    $this->withToken($first->accessToken)
        ->postJson('/auth/logout', ['refresh_token' => $second->refreshToken])
        ->assertNoContent();

    expect(familyIsLive(familyOf($first->refreshToken)))->toBeFalse()
        ->and(familyIsLive(familyOf($second->refreshToken)))->toBeFalse();
});

it('revokes the whole family, successor included, for a token rotated inside the grace window', function () {
    // The grace window treats a recently rotated token as still belonging to the live session, so
    // presenting it to logout ends that session — the sibling minted by rotation with it. Not a theft
    // signal: rotation would not have called it reuse either.
    Event::fake([RefreshTokenReused::class]);
    config(['lukk.grace_seconds' => 30]);
    $pair = User::factory()->create()->startSession();
    $successor = rotate()($pair->refreshToken);

    $this->postJson('/auth/logout', ['refresh_token' => $pair->refreshToken])->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse();
    $this->postJson('/auth/refresh', ['refresh_token' => $successor->refreshToken])->assertUnauthorized();
    Event::assertNotDispatched(RefreshTokenReused::class);
});

it('treats a consumed token presented past grace as reuse, exactly as rotation does', function () {
    Event::fake([RefreshTokenReused::class]);
    config(['lukk.grace_seconds' => 30]);
    $pair = User::factory()->create()->startSession();
    $fid = familyOf($pair->refreshToken);
    $successor = rotate()($pair->refreshToken);

    $this->travel(31)->seconds();

    $this->postJson('/auth/logout', ['refresh_token' => $pair->refreshToken])->assertNoContent();

    expect(familyIsLive($fid))->toBeFalse();
    $this->postJson('/auth/refresh', ['refresh_token' => $successor->refreshToken])->assertUnauthorized();
    Event::assertDispatched(RefreshTokenReused::class, fn ($e) => $e->familyId === $fid && $e->reason === 'reuse');
});

it('does not report an already-revoked or expired token as reuse', function () {
    // Rotation's order: revoked and expired are decided before reuse, and neither is a theft signal.
    Event::fake([RefreshTokenReused::class]);
    config(['lukk.grace_seconds' => 0]);
    $user = User::factory()->create();

    $revoked = $user->startSession();
    rotate()($revoked->refreshToken);
    revokeSession()(familyOf($revoked->refreshToken));

    $expired = $user->startSession();
    rotate()($expired->refreshToken);
    RefreshToken::where('family_id', familyOf($expired->refreshToken))->update(['expires_at' => now()->subMinute()]);

    $this->travel(5)->seconds();

    $this->postJson('/auth/logout', ['refresh_token' => $revoked->refreshToken])->assertNoContent();
    $this->postJson('/auth/logout', ['refresh_token' => $expired->refreshToken])->assertNoContent();

    Event::assertNotDispatched(RefreshTokenReused::class);
    // Both are still revoked: logging out is never refused.
    expect(familyIsLive(familyOf($expired->refreshToken)))->toBeFalse();
});

it('ignores a refresh token in the query string, as refresh does', function () {
    // RFC 9700 §4.3.2: a 30-day credential in a URL lands in access logs, proxy logs and Referer.
    $pair = expiredSession(User::factory()->create());

    $this->postJson('/auth/logout?refresh_token='.$pair->refreshToken)->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeTrue();
});

it('mounts logout without auth or a route throttle, unlike refresh', function () {
    // Not a parity argument any more: logout's CSRF defence is the request-shape check in the
    // controller, and its throttle meters only the refresh-token lookup inside EndSession — a route
    // throttle let junk /refresh traffic from a shared IP make a valid-bearer logout 429.
    $logout = routeFor('POST', 'auth/logout')->gatherMiddleware();

    expect($logout)->not->toContain('auth:api')
        ->and(collect($logout)->filter(fn ($m) => is_string($m) && str_starts_with($m, 'throttle:'))->all())->toBe([]);
});

// ---------------------------------------------------------------------------
// CSRF. The refresh cookie is SameSite=Strict, which a SAME-SITE sibling page (evil.example.com →
// api.example.com) still gets sent on a plain form POST — and even fully cross-site, the 204's
// clearing Set-Cookie is stored on a top-level navigation. So the cookie is only honoured, and only
// cleared, on a request a form cannot produce: `Content-Type: application/json` (not CORS-safelisted,
// so a cross-origin page must pass a preflight) or `Sec-Fetch-Site` of `same-origin`/`none`.
// ---------------------------------------------------------------------------

/** A form-encoded POST carrying the refresh cookie, with the given extra headers. */
function formLogout(string $refreshToken, array $headers = [])
{
    return test()->withUnencryptedCookie('__Host-refresh', $refreshToken)
        ->post('/auth/logout', [], $headers + ['Content-Type' => 'application/x-www-form-urlencoded']);
}

it('ignores the cookie on a cross-site form POST: nothing revoked, no Set-Cookie', function () {
    config(['lukk.cookie_mode' => true]);
    $pair = User::factory()->create()->startSession();

    $response = formLogout($pair->refreshToken, ['Sec-Fetch-Site' => 'cross-site'])->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeTrue()
        ->and($response->headers->getCookies())->toBeEmpty();
});

it('refuses a same-site sibling form POST, the case SameSite=Strict does not cover', function () {
    config(['lukk.cookie_mode' => true]);
    $pair = User::factory()->create()->startSession();

    $response = formLogout($pair->refreshToken, ['Sec-Fetch-Site' => 'same-site'])->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeTrue()
        ->and($response->headers->getCookies())->toBeEmpty();
});

it('refuses a text/plain body that merely mentions json in a parameter', function () {
    // `text/plain; x=/json` is CORS-safelisted (only the essence counts), so a form-free cross-site
    // fetch can send it without a preflight — while a substring check like `isJson()` accepts it.
    config(['lukk.cookie_mode' => true]);
    $pair = User::factory()->create()->startSession();

    $response = formLogout($pair->refreshToken, ['Content-Type' => 'text/plain; charset=utf-8; x=/json'])->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeTrue()
        ->and($response->headers->getCookies())->toBeEmpty();
});

it('honours the cookie on a JSON request from a sibling subdomain', function () {
    // The legitimate direct-mode SPA: app.example.com calling api.example.com with `{}` as JSON.
    config(['lukk.cookie_mode' => true]);
    $pair = User::factory()->create()->startSession();

    $response = $this->withCredentials()->withUnencryptedCookie('__Host-refresh', $pair->refreshToken)
        ->postJson('/auth/logout', [], ['Sec-Fetch-Site' => 'same-site'])
        ->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse()
        ->and(collect($response->headers->getCookies())->map->getName()->all())->toBe(['__Host-refresh']);
});

it('matches the JSON content type case- and whitespace-insensitively', function (string $contentType) {
    // Media types are case-insensitive and parameters may be padded; a client sending either must not
    // silently lose its cookie logout.
    config(['lukk.cookie_mode' => true]);
    $pair = User::factory()->create()->startSession();

    formLogout($pair->refreshToken, ['Content-Type' => $contentType, 'Sec-Fetch-Site' => 'same-site'])->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse();
})->with(['APPLICATION/JSON', ' application/json ; charset=utf-8']);

it('honours the cookie on a same-origin request that is not JSON', function () {
    config(['lukk.cookie_mode' => true]);
    $pair = User::factory()->create()->startSession();

    $response = formLogout($pair->refreshToken, ['Sec-Fetch-Site' => 'same-origin'])->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse()
        ->and(collect($response->headers->getCookies())->map->getName()->all())->toBe(['__Host-refresh']);
});

it('honours the cookie on a request with no initiator — the visitor\'s own navigation', function () {
    // `Sec-Fetch-Site: none` is a typed URL, a bookmark, a link opened in a new tab: there is no
    // originating site, so there is no cross-site page to be acting on the visitor's behalf. It is in
    // the allowlist and was documented as accepted; removing it from the list left the suite green.
    config(['lukk.cookie_mode' => true]);
    $pair = User::factory()->create()->startSession();

    $response = formLogout($pair->refreshToken, ['Sec-Fetch-Site' => 'none'])->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse()
        ->and(collect($response->headers->getCookies())->map->getName()->all())->toBe(['__Host-refresh']);
});

it('reads a body refresh_token only from a JSON body', function () {
    // An attacker cannot know the token, but one rule for every credential source is easier to keep.
    $pair = User::factory()->create()->startSession();

    $this->post('/auth/logout', ['refresh_token' => $pair->refreshToken], ['Sec-Fetch-Site' => 'same-origin'])
        ->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeTrue();
});

it('sends no Set-Cookie in cookie mode when no refresh cookie was presented', function () {
    config(['lukk.cookie_mode' => true]);

    expect($this->postJson('/auth/logout')->assertNoContent()->headers->getCookies())->toBeEmpty();
});

it('still honours a valid bearer on a form POST, which cannot carry one cross-origin', function () {
    config(['lukk.cookie_mode' => true]);
    $pair = User::factory()->create()->startSession();

    $this->withToken($pair->accessToken)
        ->post('/auth/logout', [], ['Content-Type' => 'application/x-www-form-urlencoded', 'Sec-Fetch-Site' => 'cross-site'])
        ->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse();
});

// ---------------------------------------------------------------------------
// Throttling. Only the refresh-token LOOKUP is metered, on its own per-guard, per-caller bucket with
// the refresh limits — so logout with a valid bearer can never be refused.
// ---------------------------------------------------------------------------

it('still revokes via a valid bearer when the refresh bucket is exhausted', function () {
    config(['lukk.rate_limits.refresh.max_attempts' => 2]);
    $pair = User::factory()->create()->startSession();

    $this->postJson('/auth/refresh', ['refresh_token' => 'junk-1'])->assertUnauthorized();
    $this->postJson('/auth/refresh', ['refresh_token' => 'junk-2'])->assertUnauthorized();
    $this->postJson('/auth/refresh', ['refresh_token' => 'junk-3'])->assertStatus(429);

    $this->withToken($pair->accessToken)->postJson('/auth/logout')->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse();
});

it('answers 429 with Retry-After, keeps the cookie and the session, when the lookup is throttled', function () {
    // A throttled lookup used to be skipped silently behind a 204 that also cleared the cookie: the
    // client believed it had logged out while its refresh token stayed valid (ASVS 5.0 V7.4.1). A 429
    // says nothing about whether the token exists, and leaving the cookie lets the client retry.
    config(['lukk.cookie_mode' => true, 'lukk.rate_limits.refresh.max_attempts' => 1, 'lukk.rate_limits.refresh.decay_seconds' => 60]);
    $pair = expiredSession(User::factory()->create());

    // Someone else behind the same address spends the budget.
    $this->postJson('/auth/logout', ['refresh_token' => 'junk'])->assertNoContent();

    $retry = fn () => $this->withToken($pair->accessToken)
        ->withCredentials()->withUnencryptedCookie('__Host-refresh', $pair->refreshToken)
        ->postJson('/auth/logout');

    $throttled = $retry()->assertStatus(429)->assertHeader('Retry-After');

    expect((int) $throttled->headers->get('Retry-After'))->toBeGreaterThan(0)
        ->and($throttled->headers->getCookies())->toBeEmpty()
        ->and(familyIsLive(familyOf($pair->refreshToken)))->toBeTrue();

    // Once the window has passed, the retry ends the session and clears the cookie.
    $this->travel(61)->seconds();

    $done = $retry()->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse()
        ->and(collect($done->headers->getCookies())->map->getName()->all())->toBe(['__Host-refresh']);
});

it('does not spend the lookup budget when a valid bearer is presented', function () {
    // An ordinary BFF logout sends the bearer AND the refresh token. The bearer already names and
    // revokes a family — and is itself revoked by the call, so it buys exactly one unmetered lookup —
    // so metering it let routine logouts from one BFF address exhaust the bucket for everyone behind it.
    config(['lukk.rate_limits.refresh.max_attempts' => 2]);
    $user = User::factory()->create();

    foreach (range(1, 3) as $ignored) {
        $pair = $user->startSession();
        $this->withToken($pair->accessToken)->postJson('/auth/logout', ['refresh_token' => $pair->refreshToken])->assertNoContent();
        expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse();
        app('auth')->forgetGuards();
    }

    $expired = expiredSession($user);
    $this->withToken($expired->accessToken)->postJson('/auth/logout', ['refresh_token' => $expired->refreshToken])->assertNoContent();

    expect(familyIsLive(familyOf($expired->refreshToken)))->toBeFalse();
});

it('still looks up a different-family refresh token alongside a valid bearer, when the bucket is exhausted', function () {
    // "Log me out" with an access token from one login and a cookie from a later one ends both, even
    // for a caller whose address is throttled — the valid bearer is spent by this very call.
    config(['lukk.cookie_mode' => true, 'lukk.rate_limits.refresh.max_attempts' => 1]);
    $user = User::factory()->create();
    $bearerSession = $user->startSession();
    $cookieSession = $user->startSession();

    $this->postJson('/auth/logout', ['refresh_token' => 'junk'])->assertNoContent();

    $response = $this->withToken($bearerSession->accessToken)
        ->withCredentials()->withUnencryptedCookie('__Host-refresh', $cookieSession->refreshToken)
        ->postJson('/auth/logout')
        ->assertNoContent();

    expect(familyIsLive(familyOf($bearerSession->refreshToken)))->toBeFalse()
        ->and(familyIsLive(familyOf($cookieSession->refreshToken)))->toBeFalse()
        ->and(collect($response->headers->getCookies())->map->getName()->all())->toBe(['__Host-refresh']);
});

it('does not meter a co-issuer bearer that carries a jti, since the call denylists it', function () {
    // No `fid`, but a `jti`: logout kills the token by `jti`, so it cannot be presented again and buys
    // exactly one batch of lookups — the same reasoning as a family-bearing bearer.
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);
    $cfg = Lukk::guardConfig();
    $coIssued = fn (string $jti) => JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => '1', 'jti' => $jti,
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);

    foreach (['co-1', 'co-2', 'co-3'] as $jti) {
        $this->withToken($coIssued($jti))->postJson('/auth/logout', ['refresh_token' => 'guess-'.$jti])->assertNoContent();
    }

    // The budget of one is still unspent, so an unauthenticated refresh-token logout goes through.
    $pair = expiredSession(User::factory()->create());
    $this->postJson('/auth/logout', ['refresh_token' => $pair->refreshToken])->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse();
});

it('still meters a valid bearer that cannot be revoked, since it could be replayed for more lookups', function () {
    // A co-issuer token with neither `fid` nor `jti` survives the call, so it must not buy free lookups.
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);
    $cfg = Lukk::guardConfig();
    $unrevocable = JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => '1',
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);

    $this->withToken($unrevocable)->postJson('/auth/logout', ['refresh_token' => 'guess-1'])->assertNoContent();
    $this->withToken($unrevocable)->postJson('/auth/logout', ['refresh_token' => 'guess-2'])->assertStatus(429);
});

it('never exhausts the lookup budget with logouts that present real refresh tokens', function () {
    // The budget exists to stop PROBING, and probing always misses. A token that resolves — valid,
    // rotated, revoked or expired — costs nothing, so a BFF logging many users out from one address
    // (no bearer, just their refresh tokens) is never refused.
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);
    $user = User::factory()->create();

    foreach (range(1, 4) as $ignored) {
        $pair = expiredSession($user);
        $this->postJson('/auth/logout', ['refresh_token' => $pair->refreshToken])->assertNoContent();
        expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse();
    }
});

it('does no revocation work for an already-revoked token, and counts it against the budget', function () {
    // One known token — even a long-dead one — must not let an unauthenticated caller trigger a
    // denylist write and UPDATEs on every request. A legitimate resent logout is one request.
    config(['lukk.rate_limits.refresh.max_attempts' => 2]);
    $pair = expiredSession(User::factory()->create());
    revokeSession()(familyOf($pair->refreshToken));

    $denylist = app(Denylist::class);
    $writes = new ArrayObject;
    app()->instance(Denylist::class, new class($denylist, $writes) implements Denylist
    {
        public function __construct(private Denylist $inner, private ArrayObject $writes) {}

        public function revokeJti(string $jti, int $ttlSeconds): void
        {
            $this->writes[] = 'jti';
            $this->inner->revokeJti($jti, $ttlSeconds);
        }

        public function revokeFamily(string $familyId, int $ttlSeconds): void
        {
            $this->writes[] = 'fid';
            $this->inner->revokeFamily($familyId, $ttlSeconds);
        }

        public function has(string $type, string $id): bool
        {
            return $this->inner->has($type, $id);
        }

        public function hasAny(array $types): bool
        {
            return $this->inner->hasAny($types);
        }
    });

    DB::listen(function ($query) use ($writes) {
        if (str_starts_with(strtolower($query->sql), 'update')) {
            $writes[] = 'update';
        }
    });

    $this->postJson('/auth/logout', ['refresh_token' => $pair->refreshToken])->assertNoContent();
    $this->postJson('/auth/logout', ['refresh_token' => $pair->refreshToken])->assertNoContent();
    $this->postJson('/auth/logout', ['refresh_token' => $pair->refreshToken])->assertStatus(429);

    expect($writes->getArrayCopy())->toBe([]);
});

it('counts misses, and refuses once they exhaust the budget — even for a real token', function () {
    // Refusing a real token is deliberate: whether it exists is only knowable by looking it up, and
    // the lookup is exactly what an exhausted bucket must not perform. The 429 leaves the cookie and
    // the session alone, so the client retries after Retry-After.
    config(['lukk.rate_limits.refresh.max_attempts' => 2]);
    $pair = expiredSession(User::factory()->create());

    $this->postJson('/auth/logout', ['refresh_token' => 'miss-1'])->assertNoContent();
    $this->postJson('/auth/logout', ['refresh_token' => 'miss-2'])->assertNoContent();
    $this->postJson('/auth/logout', ['refresh_token' => $pair->refreshToken])->assertStatus(429);

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeTrue();
});

it('counts every concurrent miss, and never answers differently for a hit and a miss', function () {
    // Two misses racing past the pre-check both run their lookup and both count — so the bucket ends
    // over its limit and the next request is refused. Neither racing request is answered from that
    // post-lookup count: a 429 for the miss and a 204 for a hit at the budget edge would reveal which
    // tokens exist.
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);
    $pair = expiredSession(User::factory()->create());

    $limiter = new class(app('cache')->store()) extends RateLimiter
    {
        public ?Closure $concurrent = null;

        public function tooManyAttempts($key, $maxAttempts)
        {
            // This request has READ "under the limit"; the other runs to completion before it looks up.
            $tooMany = parent::tooManyAttempts($key, $maxAttempts);
            $concurrent = $this->concurrent;
            $this->concurrent = null;
            $concurrent && $concurrent();

            return $tooMany;
        }
    };
    app()->instance(RateLimiter::class, $limiter);

    $outcomes = [];
    $run = function (string $token) use (&$outcomes) {
        try {
            app(EndSession::class)('', [$token], 'burst');
            $outcomes[] = 'ok';
        } catch (ThrottleRequestsException) {
            $outcomes[] = '429';
        }
    };

    $limiter->concurrent = fn () => $run('miss-concurrent');
    $run('miss-first');

    expect($outcomes)->toBe(['ok', 'ok'])
        ->and($limiter->attempts('lukk-logout|api|burst'))->toBe(2);

    $run($pair->refreshToken);

    expect($outcomes[2])->toBe('429')
        ->and(familyIsLive(familyOf($pair->refreshToken)))->toBeTrue();
});

it('meters logout lookups per guard, independently of the refresh route', function () {
    // Its own bucket: junk /refresh calls must not stop a cookie logout from being looked up either.
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);
    $pair = User::factory()->create()->startSession();

    $this->postJson('/auth/refresh', ['refresh_token' => 'junk'])->assertUnauthorized();
    $this->postJson('/auth/refresh', ['refresh_token' => 'junk'])->assertStatus(429);

    $this->postJson('/auth/logout', ['refresh_token' => $pair->refreshToken])->assertNoContent();

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse();
});

it('meters each guard separately — one guard\'s exhausted budget does not refuse another\'s logouts', function () {
    // The per-guard half of the key. It was pinned only by a literal-string assertion on the bucket
    // name, which says nothing about behaviour and breaks on any reformat: dropping `$this->guard`
    // from `throttleKey()` left every behavioural test in this file green, while in a multi-guard
    // install a burst of junk logouts aimed at one mount would then refuse them on every other.
    config(['lukk.rate_limits.refresh.max_attempts' => 2, 'lukk.guards.admin' => ['path' => 'admin/auth']]);
    $end = fn (string $token) => app(EndSession::class)('', [$token], 'client');

    // Spend the default guard's whole miss budget.
    $end('junk-one');
    $end('junk-two');
    expect(fn () => $end('junk-three'))->toThrow(ThrottleRequestsException::class);

    // The admin guard's budget is untouched: two of its own before it refuses, and the default guard
    // is still refusing throughout. Sharing one bucket would have refused the very first of these.
    Lukk::onGuard('admin', function () use ($end) {
        $end('junk-one');
        $end('junk-two');
        expect(fn () => $end('junk-three'))->toThrow(ThrottleRequestsException::class);
    });

    expect(fn () => $end('junk-four'))->toThrow(ThrottleRequestsException::class);
});

// ---------------------------------------------------------------------------
// The subject. Under `auth:` a valid bearer authenticated the request, so a rebound LogoutResponse
// (or anything reading `$request->user()`) saw the user. Keep that.
// ---------------------------------------------------------------------------

it('authenticates the request as the bearer\'s user before the session is revoked', function () {
    $user = User::factory()->create();
    $pair = $user->startSession();

    app()->bind(LogoutResponse::class, fn () => new class implements LogoutResponse
    {
        public function toResponse($request)
        {
            return response()->json(['user' => $request->user()?->getAuthIdentifier(), 'default' => auth()->id()]);
        }
    });

    $this->withToken($pair->accessToken)->postJson('/auth/logout')
        ->assertOk()
        ->assertExactJson(['user' => $user->getKey(), 'default' => $user->getKey()]);

    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse();
});

it('leaves the request unauthenticated when only a refresh token names the session', function () {
    $pair = User::factory()->create()->startSession();

    app()->bind(LogoutResponse::class, fn () => new class implements LogoutResponse
    {
        public function toResponse($request)
        {
            return response()->json(['user' => $request->user()?->getAuthIdentifier()]);
        }
    });

    $this->postJson('/auth/logout', ['refresh_token' => $pair->refreshToken])->assertOk()->assertExactJson(['user' => null]);
    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse();
});

// ---------------------------------------------------------------------------
// Boundaries the suite would otherwise let drift.
// ---------------------------------------------------------------------------

it('keeps a co-issuer token denied for the rest of its life, not for a token second', function () {
    $cfg = Lukk::guardConfig();
    $token = JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => '1', 'jti' => 'co-issued-ttl',
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);

    $this->withToken($token)->postJson('/auth/logout')->assertNoContent();

    // Past a 1-second TTL but well inside the token's own lifetime (which firebase checks on real time).
    $this->travel(120)->seconds();

    expect(app(Denylist::class)->has('jti', 'co-issued-ttl'))->toBeTrue()
        ->and(verifier()->verify($token))->toBeNull();
});

it('does not call a token presented at exactly the end of grace reuse (pins < not <=)', function () {
    Event::fake([RefreshTokenReused::class]);
    config(['lukk.grace_seconds' => 30]);
    $pair = User::factory()->create()->startSession();
    rotate()($pair->refreshToken);

    $this->travel(30)->seconds();   // rotated_at + grace === now

    $this->postJson('/auth/logout', ['refresh_token' => $pair->refreshToken])->assertNoContent();

    Event::assertNotDispatched(RefreshTokenReused::class);
    expect(familyIsLive(familyOf($pair->refreshToken)))->toBeFalse();
});
