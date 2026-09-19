<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Lukk\Http\Responses\LoginResponse;
use Lukk\Http\Responses\LogoutResponse;
use Lukk\Lukk;
use Lukk\Support\TokenPair;

function emit(TokenPair $pair)
{
    return (new LoginResponse($pair))->toResponse(Request::create('/auth/login', 'POST'));
}

it('returns both tokens in the JSON body in BFF mode (default)', function () {
    config(['lukk.cookie_mode' => false]);

    $response = emit(new TokenPair('access.jwt', 'opaque-refresh', 900));
    $body = $response->getData(true);

    expect($body)->toMatchArray([
        'access_token' => 'access.jwt',
        'refresh_token' => 'opaque-refresh',
        'token_type' => 'Bearer',
        'expires_in' => 900,
    ]);
    expect($response->headers->getCookies())->toBeEmpty();
});

it('marks token responses as non-cacheable (no-store) in both modes', function () {
    config(['lukk.cookie_mode' => false]);
    expect(emit(new TokenPair('a', 'b', 900))->headers->get('Cache-Control'))->toContain('no-store');

    config(['lukk.cookie_mode' => true]);
    expect(emit(new TokenPair('a', 'b', 900))->headers->get('Cache-Control'))->toContain('no-store');
});

it('puts the refresh token in a __Host- cookie and omits it from the body in cookie mode', function () {
    config(['lukk.cookie_mode' => true]);

    $response = emit(new TokenPair('access.jwt', 'opaque-refresh', 900));
    $body = $response->getData(true);

    expect($body)->not->toHaveKey('refresh_token');
    expect($body['access_token'])->toBe('access.jwt');

    $cookies = $response->headers->getCookies();
    expect($cookies)->toHaveCount(1);

    $cookie = $cookies[0];
    expect($cookie->getName())->toBe('__Host-refresh');
    expect($cookie->getValue())->toBe('opaque-refresh');
    // __Host- prefix requirements: Secure, Path=/, no Domain. Plus HttpOnly.
    expect($cookie->isSecure())->toBeTrue();
    expect($cookie->isHttpOnly())->toBeTrue();
    expect($cookie->getPath())->toBe('/');
    expect($cookie->getDomain())->toBeNull();
});

it('carries no Domain even under SESSION_DOMAIN — a __Host- cookie with one is discarded', function () {
    // `CookieJar` resolves the domain as `$domain ?: $this->domain`, and its default is seeded from
    // `session.domain`. Both `null` and `''` are falsy, so passing `domain: null` was NOT "no Domain" —
    // it was "fall back to SESSION_DOMAIN". An app sharing a web session across subdomains therefore
    // emitted `__Host-refresh` WITH `domain=.example.com`, which rfc6265bis §4.1.3.2 makes the browser
    // ignore entirely: login answered 200, no cookie was stored, and the visitor was silently signed
    // out when the access token lapsed. Testbench leaves `session.domain` null, so nothing exercised
    // the fallback.
    config(['lukk.cookie_mode' => true, 'session.domain' => '.example.com']);
    app()->forgetInstance('cookie');

    $set = emit(new TokenPair('access.jwt', 'opaque-refresh', 900))->headers->getCookies()[0];
    $clear = app(LogoutResponse::class)->toResponse(request())->headers->getCookies()[0];

    expect($set->getName())->toBe('__Host-refresh')
        ->and($set->getDomain())->toBeNull()
        ->and((string) $set)->not->toContain('domain=')
        // The clear has to match the set, or the cookie it exists to remove stays put.
        ->and($clear->getName())->toBe('__Host-refresh')
        ->and($clear->getDomain())->toBeNull();
});

it('drops Secure and the __Host- prefix when lukk.cookie.secure is off (dev over http)', function () {
    config(['lukk.cookie_mode' => true, 'lukk.cookie.secure' => false]);

    $cookie = emit(new TokenPair('access.jwt', 'opaque-refresh', 900))->headers->getCookies()[0];

    // __Host- REQUIRES Secure, so the prefix is stripped when Secure is off — else the browser rejects it.
    expect($cookie->getName())->toBe('refresh');
    expect($cookie->isSecure())->toBeFalse();
    expect($cookie->isHttpOnly())->toBeTrue();
    expect($cookie->getPath())->toBe('/');
});

it('clears the refresh cookie on logout in cookie mode', function () {
    config(['lukk.cookie_mode' => true]);

    $response = (new LogoutResponse)->toResponse(Request::create('/auth/logout', 'POST'));

    expect($response->getStatusCode())->toBe(204);
    $cookies = $response->headers->getCookies();
    expect($cookies)->toHaveCount(1);
    expect($cookies[0]->getName())->toBe('__Host-refresh');
    // A forget cookie carries no value and an expiry in the past.
    expect((string) $cookies[0]->getValue())->toBe('');
    expect($cookies[0]->getExpiresTime())->toBeLessThan(time());
    // Same attributes as the cookie it removes, HttpOnly included.
    expect($cookies[0]->isHttpOnly())->toBeTrue();
});

it('emits no cookie on logout when cookie_mode is unset — body mode is the default', function () {
    $lukk = (array) config('lukk');
    unset($lukk['cookie_mode']);
    config()->set('lukk', $lukk);

    expect((new LogoutResponse)->toResponse(Request::create('/auth/logout', 'POST'))->headers->getCookies())->toBeEmpty();
});

it('emits no cookie on logout in BFF mode', function () {
    config(['lukk.cookie_mode' => false]);

    $response = (new LogoutResponse)->toResponse(Request::create('/auth/logout', 'POST'));

    expect($response->getStatusCode())->toBe(204);
    expect($response->headers->getCookies())->toBeEmpty();
});

it('clears the refresh cookie on logout per the guard\'s own cookie_mode', function () {
    // `EmitsTokens` reads `cookie_mode` through the guard config; logout read the global key. A guard
    // that opted INTO cookie mode set a cookie at login that logout then never cleared, and a guard
    // that opted OUT was sent a stray clear for a cookie it never had.
    config(['lukk.cookie_mode' => false, 'lukk.guards.admin' => ['cookie_mode' => true]]);

    $admin = Lukk::onGuard('admin', fn () => (new LogoutResponse)->toResponse(Request::create('/admin/auth/logout', 'POST')));
    $users = (new LogoutResponse)->toResponse(Request::create('/auth/logout', 'POST'));

    expect($admin->headers->getCookies())->toHaveCount(1)
        ->and($admin->headers->getCookies()[0]->getName())->toBe('__Host-refresh-admin')
        ->and($admin->headers->getCookies()[0]->getExpiresTime())->toBeLessThan(time())
        ->and($users->headers->getCookies())->toBeEmpty();

    config(['lukk.cookie_mode' => true, 'lukk.guards.admin' => ['cookie_mode' => false]]);

    expect(Lukk::onGuard('admin', fn () => (new LogoutResponse)->toResponse(Request::create('/admin/auth/logout', 'POST')))
        ->headers->getCookies())->toBeEmpty();
});
