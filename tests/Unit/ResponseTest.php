<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Lukk\Http\Responses\LoginResponse;
use Lukk\Http\Responses\LogoutResponse;
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
});

it('emits no cookie on logout in BFF mode', function () {
    config(['lukk.cookie_mode' => false]);

    $response = (new LogoutResponse)->toResponse(Request::create('/auth/logout', 'POST'));

    expect($response->getStatusCode())->toBe(204);
    expect($response->headers->getCookies())->toBeEmpty();
});
