<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Lukk\Actions\StartSession;
use Lukk\Contracts\TokenVerifier;
use Lukk\Http\Middleware\RequirePinnedAbility;
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
            'user' => actor()->tokenCan('orders.read'),
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
        'can' => actor()->tokenCan('orders.read'),
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

it('keeps an assumed token per guard, instead of clobbering the previous one', function () {
    // `put()` is keyed by guard; a single-slot `assume()` meant a multi-guard test acting as an
    // admin and then as a user silently lost the first, and `$admin->tokenCan()` came back false
    // with nothing to explain it.
    $admin = User::factory()->create();
    $user = User::factory()->create();

    Lukk::actingAs($admin, 'admin', ['admin.all']);
    Lukk::actingAs($user, config('lukk.guard'), ['orders.read']);

    $assumed = app(VerifiedToken::class);

    expect($assumed['admin']->abilities->all())->toBe(['admin.all'])
        ->and($assumed[config('lukk.guard')]->abilities->all())->toBe(['orders.read']);
});

it('gates the session routes on EVERY guard, not just the default', function () {
    // The gate was added to the default-guard block only, while the extra-guard loop mounted the
    // same two routes untouched — so a token pinned to a narrow grant could log an ADMIN account
    // out everywhere, which is exactly the mount a multi-guard install cares about.
    $admin = Admin::factory()->create();
    $victim = $admin->startSession();
    app('auth')->forgetGuards();

    // Resolved INSIDE `onGuard` so the Action captures the admin guard's issuer, repository and
    // audience — the same reason `HasRefreshTokens::startSession()` does it that way.
    $pat = Lukk::onGuard('admin', fn () => app(StartSession::class)($admin->getKey(), [], ['ci.deploy']));

    $this->withToken($pat->accessToken)->deleteJson('/admin/auth/sessions')->assertStatus(403);
    app('auth')->forgetGuards();
    $this->withToken($pat->accessToken)->deleteJson('/admin/auth/sessions/others')->assertStatus(403);
    app('auth')->forgetGuards();

    // The session it tried to kill is still alive.
    $this->withToken($victim->accessToken)->postJson('/admin/auth/logout')->assertSuccessful();
});

it('structurally requires the gate on every mounted session-revoking route', function () {
    // Belt and braces for the class of bug above: a future guard block, or a route added to one
    // copy and not another, fails here rather than in someone's production logs.
    $unguarded = collect(Route::getRoutes()->getRoutes())
        ->filter(fn ($route) => in_array('DELETE', $route->methods(), true)
            && str_contains($route->uri(), 'sessions'))
        ->reject(fn ($route) => collect($route->gatherMiddleware())
            ->contains(fn ($m) => str_starts_with((string) $m, RequirePinnedAbility::class.':')))
        ->map(fn ($route) => $route->uri())
        ->values()
        ->all();

    expect($unguarded)->toBe([])
        ->and(collect(Route::getRoutes()->getRoutes())
            ->filter(fn ($r) => in_array('DELETE', $r->methods(), true) && str_contains($r->uri(), 'sessions'))
            ->count())->toBeGreaterThanOrEqual(4);   // both guards × {sessions, sessions/others}
});

it('honours a features flag set on a guard, not just the global one', function () {
    // `guardConfig()` deep-merges `lukk.guards.{name}` over the top level, so a deployment can
    // switch a feature on for one guard. Both new flags read the GLOBAL block instead, silently
    // dropping that — and both fail OPEN, so the narrowest token the API can issue kept logging the
    // admin account out everywhere on a guard that had explicitly asked for the gate.
    config(['lukk.features.gate_auth_routes' => false]);
    config(['lukk.guards.admin.features' => ['gate_auth_routes' => true]]);

    $admin = Admin::factory()->create();
    $pat = Lukk::onGuard('admin', fn () => app(StartSession::class)($admin->getKey(), [], ['ci.deploy']));

    $this->withToken($pat->accessToken)->deleteJson('/admin/auth/sessions')->assertStatus(403);
});

it('honours a per-guard abilities flag, so a claims hook cannot become the authorization layer', function () {
    // With the flag read globally, `usesAbilities()` was false on the admin guard even though its
    // own config said true — so the issuer skipped the `scope` reservation and a decorative
    // `tokenClaimsUsing` scope was signed and honoured by the gates.
    config(['lukk.features.abilities' => false]);
    config(['lukk.guards.admin.features' => ['abilities' => true]]);
    Lukk::tokenClaimsUsing(fn () => ['scope' => 'admin.everything']);

    $admin = Admin::factory()->create();
    $pair = Lukk::onGuard('admin', fn () => app(StartSession::class)($admin->getKey()));
    Lukk::$tokenClaimsUsing = null;

    $claims = (array) Lukk::onGuard('admin', fn () => app(TokenVerifier::class))->verify($pair->accessToken);

    expect($claims)->not->toHaveKey('scope');
});

it('follows the token\'s guard for the feature flag, not the ambient one', function () {
    // The Actions capture their guard at RESOLVE time so an Action resolved inside `Lukk::onGuard`
    // and invoked outside it can't mint against the wrong identity. `usesAbilities()` still read the
    // ambient guard, so the two halves disagreed: the callback followed the captured guard and the
    // flag followed whatever was current — minting an admin-audience token whose `scope` came from
    // a claims hook, which lukk's own gates then honour.
    config(['lukk.features.abilities' => false]);
    config(['lukk.guards.admin.features' => ['abilities' => true]]);
    Lukk::tokenClaimsUsing(fn () => ['scope' => 'admin.everything']);

    $admin = Admin::factory()->create();
    $action = Lukk::onGuard('admin', fn () => app(StartSession::class));   // resolved on admin...
    $pair = $action($admin->getKey());                                     // ...invoked on api

    Lukk::$tokenClaimsUsing = null;

    $claims = (array) Lukk::onGuard('admin', fn () => app(TokenVerifier::class))
        ->verify($pair->accessToken);

    expect($claims['aud'])->toBe('https://admin.test')
        ->and($claims)->not->toHaveKey('scope');
});
