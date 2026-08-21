<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Lukk\Lukk;
use Lukk\Tests\Fixtures\User;

uses()->group('abilities');

beforeEach(function () {
    Route::middleware(['auth:api', 'lukk.ability:orders.read,orders.write'])
        ->get('/_test/any', fn () => response()->json(['ok' => true]));
    Route::middleware(['auth:api', 'lukk.abilities:orders.read,orders.write'])
        ->get('/_test/all', fn () => response()->json(['ok' => true]));
});

afterEach(fn () => Lukk::$abilitiesUsing = null);

it('mints no scope claim until abilities are configured', function () {
    // An install that never opts in keeps byte-identical tokens.
    $pair = User::factory()->create()->startSession();

    expect((array) verifier()->verify($pair->accessToken))->not->toHaveKey('scope');
});

it('mints the granted abilities as a space-delimited scope claim', function () {
    Lukk::abilitiesUsing(fn () => ['orders.read', 'orders.write']);
    $pair = User::factory()->create()->startSession();

    expect(verifier()->verify($pair->accessToken)->scope)->toBe('orders.read orders.write');
});

it('lets a token through when it holds ANY of the required abilities', function () {
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $access = User::factory()->create()->startSession()->accessToken;

    $this->withToken($access)->getJson('/_test/any')->assertOk();
    // ...but `abilities:` requires all of them.
    app('auth')->forgetGuards();
    $this->withToken($access)->getJson('/_test/all')->assertStatus(403);
});

it('lets a token through when it holds ALL of them', function () {
    Lukk::abilitiesUsing(fn () => ['orders.read', 'orders.write']);
    $access = User::factory()->create()->startSession()->accessToken;

    $this->withToken($access)->getJson('/_test/all')->assertOk();
});

it('refuses a token holding none of them', function () {
    Lukk::abilitiesUsing(fn () => ['users.read']);
    $access = User::factory()->create()->startSession()->accessToken;

    $this->withToken($access)->getJson('/_test/any')->assertStatus(403);
});

it('refuses a token with no scope at all, rather than passing it', function () {
    // Deny by default. Adding the middleware while forgetting `abilitiesUsing` must fail loudly,
    // not wave every request through — a permission check that passes when nothing was configured
    // is worse than one that breaks.
    $access = User::factory()->create()->startSession()->accessToken;

    $this->withToken($access)->getJson('/_test/any')->assertStatus(403);
});

it('honours a prefix wildcard end to end', function () {
    Lukk::abilitiesUsing(fn () => ['orders.*']);
    $access = User::factory()->create()->startSession()->accessToken;

    $this->withToken($access)->getJson('/_test/any')->assertOk();
});

it('exposes the TOKEN\'s abilities on the user, not the user\'s', function () {
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;

    Route::middleware('auth:api')->get('/_test/can', fn () => response()->json([
        'read' => request()->user()->tokenCan('orders.read'),
        'write' => request()->user()->tokenCan('orders.write'),
    ]));

    $this->withToken($access)->getJson('/_test/can')
        ->assertOk()
        ->assertJson(['read' => true, 'write' => false]);
});

it('re-derives abilities on refresh, so a revoked one expires with the access token', function () {
    // Deliberately NOT frozen at login: abilities live in the callback, so revoking one takes
    // effect within access_ttl instead of lasting the life of the refresh token. This is the reason
    // they are not stored on the family row.
    Lukk::abilitiesUsing(fn () => ['orders.read', 'orders.write']);
    $pair = User::factory()->create()->startSession();
    expect(verifier()->verify($pair->accessToken)->scope)->toBe('orders.read orders.write');

    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $rotated = rotate()($pair->refreshToken);

    expect(verifier()->verify($rotated->accessToken)->scope)->toBe('orders.read');
});

it('refuses an unauthenticated caller before the ability check', function () {
    $this->getJson('/_test/any')->assertStatus(401);
});

it('reports tokenCannot, and grants nothing outside an authenticated request', function () {
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $user = User::factory()->create();

    // A model that was never through the guard has no token, so it can do nothing — rather than
    // silently reporting whatever the last request happened to carry.
    expect($user->tokenCannot('orders.read'))->toBeTrue()
        ->and($user->tokenAbilities()->all())->toBe([]);

    Route::middleware('auth:api')->get('/_test/cannot', fn () => response()->json([
        'cannotWrite' => request()->user()->tokenCannot('orders.write'),
        'cannotRead' => request()->user()->tokenCannot('orders.read'),
    ]));

    $this->withToken($user->startSession()->accessToken)->getJson('/_test/cannot')
        ->assertJson(['cannotWrite' => true, 'cannotRead' => false]);
});
