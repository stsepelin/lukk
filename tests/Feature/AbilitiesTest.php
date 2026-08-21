<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Route;
use Lukk\Lukk;
use Lukk\Models\RefreshToken;
use Lukk\Support\TokenContext;
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

it('pins a session\'s own abilities, surviving refresh and ignoring the user\'s grant', function () {
    // The shape a personal access token needs: the TOKEN owns the grant, not the user. Without
    // this, a PAT would silently become a user-derived token on its first refresh.
    Lukk::abilitiesUsing(fn () => ['*']);              // the user can do everything...
    $user = User::factory()->create();
    $pair = start()($user->getKey(), [], ['ci.deploy']); // ...this token can do one thing

    expect(verifier()->verify($pair->accessToken)->scope)->toBe('ci.deploy');

    // And it stays pinned across rotation, even as the user's grant changes underneath. Rotated
    // TWICE deliberately: the grant has to be written onto each successor row, not just read off
    // the parent — carrying it only into the minted token would lose it on the NEXT refresh.
    Lukk::abilitiesUsing(fn () => ['admin.*']);
    $rotated = rotate()($pair->refreshToken);
    expect(verifier()->verify($rotated->accessToken)->scope)->toBe('ci.deploy');

    $again = rotate()($rotated->refreshToken);
    expect(verifier()->verify($again->accessToken)->scope)->toBe('ci.deploy');
});

it('still derives per mint when the session pins nothing', function () {
    // The default. Keeps a revoked ability taking effect within access_ttl rather than lasting the
    // life of the refresh token — the property that makes storage OPTIONAL rather than the norm.
    Lukk::abilitiesUsing(fn () => ['orders.read', 'orders.write']);
    $pair = User::factory()->create()->startSession();

    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $rotated = rotate()($pair->refreshToken);

    expect(verifier()->verify($rotated->accessToken)->scope)->toBe('orders.read');
});

it('refuses a malformed grant loudly instead of minting a wider token', function () {
    // A space would split one ability into two — `['orders.read admin']` granting `admin`, which
    // nobody issued. Reachable the moment ability names come from data (a tenant role, a DB column).
    Lukk::abilitiesUsing(fn () => ['orders.read admin']);

    expect(fn () => User::factory()->create()->startSession())
        ->toThrow(InvalidArgumentException::class, 'not a valid scope token');
});

it('lets an empty grant ERASE a scope a claims hook set', function () {
    // The deny path must be able to erase, not merely fail to write: `abilitiesUsing` returning []
    // for a suspended user previously still minted the hook's `admin.*`.
    Lukk::tokenClaimsUsing(fn () => ['scope' => 'admin.*']);
    Lukk::abilitiesUsing(fn () => []);

    $pair = User::factory()->create()->startSession();

    expect((array) verifier()->verify($pair->accessToken))->not->toHaveKey('scope');

    Lukk::$tokenClaimsUsing = null;
});

it('does not let a claims hook forge a scope the abilities layer did not grant', function () {
    Lukk::tokenClaimsUsing(fn () => ['scope' => 'admin.*']);
    Lukk::abilitiesUsing(fn () => ['orders.read']);

    $pair = User::factory()->create()->startSession();

    expect(verifier()->verify($pair->accessToken)->scope)->toBe('orders.read');

    Lukk::$tokenClaimsUsing = null;
});

it('does not revoke the family when the abilities callback fails during refresh', function () {
    // The callback is documented as running on every refresh and expected to hit a permission
    // store, so it WILL fail sometimes. Minting after the transaction committed meant the parent
    // was consumed while the client never received the successor — and the retry then read as a
    // replay: reuse detection, whole family revoked, every device logged out from a transient blip.
    $this->freezeSecond();
    config(['lukk.grace_seconds' => 30]);
    $pair = User::factory()->create()->startSession();

    Lukk::abilitiesUsing(fn () => throw new RuntimeException('permission store down'));
    expect(fn () => rotate()($pair->refreshToken))->toThrow(RuntimeException::class);
    Lukk::$abilitiesUsing = null;

    // Well past the grace window, so a consumed parent would be classed as reuse.
    $this->travel(45)->seconds(function () use ($pair) {
        expect(fn () => rotate()($pair->refreshToken))->not->toThrow(Exception::class);
    });

    expect(RefreshToken::whereNull('revoked_at')->count())->toBeGreaterThan(0);
});

it('gates on the TOKEN\'s scope, not on what the user could be granted now', function () {
    // The whole feature in one assertion. A gate that re-derives from the user makes every ability
    // check ignore the token it was handed — a narrow PAT would act with the owner's full rights.
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $access = User::factory()->create()->startSession()->accessToken;

    Lukk::abilitiesUsing(fn () => ['*']);              // the user is promoted mid-session...

    $this->withToken($access)->getJson('/_test/all')->assertStatus(403);   // ...the token is not
});

it('ignores a scope the client supplies alongside the token', function () {
    // `scope` is a claim, not an input. Reading request data here would let anyone name their own
    // permissions — the request is attacker-controlled, the signed token is not.
    Lukk::abilitiesUsing(fn () => ['users.read']);
    $access = User::factory()->create()->startSession()->accessToken;

    $this->withToken($access)
        ->withHeaders(['X-Scope' => 'orders.read', 'Scope' => 'orders.read'])
        ->getJson('/_test/any?scope=orders.read&abilities[]=orders.write')
        ->assertStatus(403);
});

it('never reads a scope out of a token that failed verification', function () {
    // A JWT is readable without the key — only the signature makes it trustworthy. Parsing claims
    // before verifying would let anyone hand-write `scope: *` and walk through every gate.
    $forged = JWT::encode([
        'iss' => config('lukk.issuer'),
        'aud' => config('lukk.audience')[0],
        'sub' => (string) User::factory()->create()->getKey(),
        'fid' => 'forged', 'jti' => 'forged',
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
        'scope' => '*',
    ], str_repeat('z', 64), 'HS256');

    $this->withToken($forged)->getJson('/_test/any')->assertStatus(401);
});

it('answers with the scope that would have sufficed, per RFC 6750', function () {
    // `insufficient_scope` is the registered way to say "authenticated, but not for this" — an API
    // gateway or a generic OAuth client can act on it without knowing anything about lukk.
    Lukk::abilitiesUsing(fn () => ['users.read']);
    $access = User::factory()->create()->startSession()->accessToken;

    $response = $this->withToken($access)->getJson('/_test/all')->assertStatus(403);

    expect($response->headers->get('WWW-Authenticate'))
        ->toContain('error="insufficient_scope"')
        ->toContain('scope="orders.read orders.write"');
});

it('answers 401, not 403, when the gate is reached with no token at all', function () {
    // Defence in depth: the middleware priority puts `auth:api` first, but a route that forgot it
    // must still say "log in" rather than "you are refused" — a 403 stops a client retrying.
    Route::middleware('lukk.ability:orders.read')->get('/_test/naked', fn () => response()->json(['ok' => true]));

    $this->getJson('/_test/naked')->assertStatus(401);
});

it('gates before the route runs even when written after the auth middleware', function () {
    // Middleware runs in the order declared UNLESS the class is in the kernel's priority list.
    // `Authenticate` is; without registering the gates after it, `['lukk.ability:x', 'auth:api']`
    // would gate an unauthenticated request and answer 401 for a perfectly good token.
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    Route::middleware(['lukk.ability:orders.read', 'auth:api'])
        ->get('/_test/reordered', fn () => response()->json(['ok' => true]));

    $this->withToken(User::factory()->create()->startSession()->accessToken)
        ->getJson('/_test/reordered')->assertOk();
});

it('refuses to run a gate that requires nothing', function () {
    // `lukk.ability:` with no arguments is a route-definition bug. Denying would hide it behind a
    // 403 someone debugs as a permissions problem.
    Route::middleware(['auth:api', 'lukk.ability:'])->get('/_test/empty', fn () => response()->json([]));
    Lukk::abilitiesUsing(fn () => ['*']);

    $this->withoutExceptionHandling()
        ->withToken(User::factory()->create()->startSession()->accessToken);

    expect(fn () => $this->getJson('/_test/empty'))
        ->toThrow(InvalidArgumentException::class, 'needs at least one ability');
});

it('keeps a "0" ability instead of filtering it away', function () {
    // Bare `array_filter` drops `'0'` as falsy. In an ALL list that silently REMOVES a requirement.
    Route::middleware(['auth:api', 'lukk.abilities:0,orders.read'])
        ->get('/_test/zero', fn () => response()->json(['ok' => true]));
    Lukk::abilitiesUsing(fn () => ['orders.read']);

    $this->withToken(User::factory()->create()->startSession()->accessToken)
        ->getJson('/_test/zero')->assertStatus(403);
});

it('hands the abilities callback the guard and the family it is minting for', function () {
    // A multi-guard install serves different audiences from one user table often enough that `['*']`
    // for a customer token and `['*']` for an admin one are not the same grant.
    $seen = null;
    Lukk::abilitiesUsing(function ($userId, $context) use (&$seen) {
        $seen = $context;

        return ['orders.read'];
    });

    $pair = User::factory()->create()->startSession();

    expect($seen)->toBeInstanceOf(TokenContext::class)
        ->and($seen->guard)->toBe(config('lukk.guard'))
        ->and($seen->familyId)->toBe(verifier()->verify($pair->accessToken)->fid);
});

it('lets actingAs stand in for a token, so ability-gated routes are testable', function () {
    $user = User::factory()->create();

    Lukk::actingAs($user, config('lukk.guard'), ['orders.read']);

    $this->getJson('/_test/any')->assertOk();
    expect($user->tokenCan('orders.read'))->toBeTrue()
        ->and($user->tokenCan('orders.write'))->toBeFalse();
});

it('denies — rather than 401s — a caller authenticated without a lukk token', function () {
    // `actingAs` with no abilities, a session guard, anything that authenticates by another route.
    // The caller IS known, they just hold nothing: 403 (deny by default), not "please log in".
    Lukk::actingAs(User::factory()->create(), config('lukk.guard'));

    $this->getJson('/_test/any')->assertStatus(403);
});

it('accepts a Collection from the callback, not just an array', function () {
    // A permissions relation is the likeliest real implementation and returns a Collection. A bare
    // `(array)` cast on one yields a NESTED array, which reached `strval()` and 500'd every login
    // and every refresh — the whole app down on the first request after wiring abilities up.
    Lukk::abilitiesUsing(fn () => collect(['orders.read', 'orders.write']));

    expect(verifier()->verify(User::factory()->create()->startSession()->accessToken)->scope)
        ->toBe('orders.read orders.write');
});

it('accepts a single ability returned bare, without an array around it', function () {
    Lukk::abilitiesUsing(fn () => 'orders.read');

    expect(verifier()->verify(User::factory()->create()->startSession()->accessToken)->scope)
        ->toBe('orders.read');
});

it('never lets an assumed token override a real, verified one', function () {
    // `actingAs` writes a token with no bearer behind it. If that ever took precedence, a single
    // call left over in a test helper — or in an application that reached for it — would hand every
    // subsequent request the assumed grant instead of the one its token actually carries.
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;

    Lukk::actingAs($user, config('lukk.guard'), ['*']);
    app('auth')->forgetGuards();   // ...so the real guard resolves the bearer token below

    $this->withToken($access)->getJson('/_test/all')->assertStatus(403);
});
