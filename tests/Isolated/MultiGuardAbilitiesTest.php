<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Lukk\Lukk;
use Lukk\Support\VerifiedToken;
use Lukk\Tests\Fixtures\Admin;
use Lukk\Tests\Fixtures\User;
use Lukk\Tests\MultiGuardTestCase;

uses(MultiGuardTestCase::class)->group('abilities', 'multi-guard');

afterEach(fn () => Lukk::$abilitiesUsing = null);

beforeEach(function () {
    Route::middleware(['auth:api', 'lukk.ability:orders.read'])
        ->get('/_test/user-orders', fn () => response()->json(['ok' => true]));
    Route::middleware(['auth:admin', 'lukk.ability:orders.read'])
        ->get('/_test/admin-orders', fn () => response()->json(['ok' => true]));
});

it('grants per guard, so the same id gets different abilities on each', function () {
    // One user table per guard here, but the ids collide — and plenty of installs serve an `admin`
    // and a `customer` guard from ONE table. `['*']` for a customer is not `['*']` for an admin, so
    // the callback has to be told which is being minted.
    Lukk::abilitiesUsing(fn ($userId, $context) => $context->guard === 'admin' ? ['orders.read'] : ['orders.write']);

    $user = User::factory()->create();
    $admin = Admin::factory()->create();
    expect($admin->getKey())->toBe($user->getKey());   // the ids really do collide

    $userToken = $user->startSession()->accessToken;
    app('auth')->forgetGuards();
    $adminToken = $admin->startSession()->accessToken;

    app('auth')->forgetGuards();
    $this->withToken($adminToken)->getJson('/_test/admin-orders')->assertOk();
    app('auth')->forgetGuards();
    $this->withToken($userToken)->getJson('/_test/user-orders')->assertStatus(403);
});

it('does not let one guard\'s grant answer for a colliding id on another', function () {
    // `forUser` matches on class AND id. On id alone, Admin #1 would read User #1's grant.
    Lukk::abilitiesUsing(fn ($userId, $context) => $context->guard === 'admin' ? [] : ['orders.read']);

    $user = User::factory()->create();
    $admin = Admin::factory()->create();

    Route::middleware('auth:api')->get('/_test/cross', function () use ($admin) {
        return response()->json([
            'user' => request()->user()->tokenCan('orders.read'),
            'admin' => $admin->tokenCan('orders.read'),
        ]);
    });

    $this->withToken($user->startSession()->accessToken)->getJson('/_test/cross')
        ->assertJson(['user' => true, 'admin' => false]);
});

it('reports each request\'s own token, never the previous request\'s', function () {
    // Abilities on the user MODEL would survive the request that set them: anything holding a user
    // across requests — a memoized guard, a container binding, an Octane worker — would then answer
    // an authorization question from a grant that expired with the last visitor.
    Lukk::abilitiesUsing(fn ($userId) => $userId === 1 ? ['orders.read'] : []);

    $wide = User::factory()->create();
    $narrow = User::factory()->create();
    expect($wide->getKey())->toBe(1);

    Route::middleware('auth:api')->get('/_test/who', fn () => response()->json([
        'can' => request()->user()->tokenCan('orders.read'),
    ]));

    $this->withToken($wide->startSession()->accessToken)->getJson('/_test/who')->assertJson(['can' => true]);
    app('auth')->forgetGuards();
    $this->withToken($narrow->startSession()->accessToken)->getJson('/_test/who')->assertJson(['can' => false]);
});

it('keeps the two guards\' tokens apart within one request', function () {
    Lukk::abilitiesUsing(fn ($userId, $context) => $context->guard === 'admin' ? ['admin.all'] : ['orders.read']);

    $user = User::factory()->create();
    $admin = Admin::factory()->create();
    $adminToken = $admin->startSession()->accessToken;
    app('auth')->forgetGuards();

    Route::middleware('auth:api')->get('/_test/both', function () use ($adminToken) {
        // A second guard resolving inside the same request must record its own token, not overwrite.
        request()->headers->set('Authorization', 'Bearer '.$adminToken);
        auth('admin')->user();

        return response()->json([
            'api' => VerifiedToken::current(request(), 'api')?->abilities->all(),
            'admin' => VerifiedToken::current(request(), 'admin')?->abilities->all(),
        ]);
    });

    $this->withToken($user->startSession()->accessToken)->getJson('/_test/both')
        ->assertJson(['api' => ['orders.read'], 'admin' => ['admin.all']]);
});
