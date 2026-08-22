<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Contracts\TokenIssuer;
use Lukk\Events\RefreshTokenReused;
use Lukk\Events\TokenAbilityDenied;
use Lukk\Exceptions\InvalidRefreshToken;
use Lukk\Http\Middleware\RequirePinnedAbility;
use Lukk\Http\Resources\UserResource;
use Lukk\Lukk;
use Lukk\Models\RefreshToken;
use Lukk\Refresh\DatabaseRefreshTokenRepository;
use Lukk\Support\Abilities;
use Lukk\Support\TokenContext;
use Lukk\Support\VerifiedToken;
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

    expect((array) claims($pair->accessToken))->not->toHaveKey('scope');
});

it('mints the granted abilities as a space-delimited scope claim', function () {
    Lukk::abilitiesUsing(fn () => ['orders.read', 'orders.write']);
    $pair = User::factory()->create()->startSession();

    expect(claims($pair->accessToken)->scope)->toBe('orders.read orders.write');
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
        'read' => actor()->tokenCan('orders.read'),
        'write' => actor()->tokenCan('orders.write'),
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
    expect(claims($pair->accessToken)->scope)->toBe('orders.read orders.write');

    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $rotated = rotate()($pair->refreshToken);

    expect(claims($rotated->accessToken)->scope)->toBe('orders.read');
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
        'cannotWrite' => actor()->tokenCannot('orders.write'),
        'cannotRead' => actor()->tokenCannot('orders.read'),
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

    expect(claims($pair->accessToken)->scope)->toBe('ci.deploy');

    // And it stays pinned across rotation, even as the user's grant changes underneath. Rotated
    // TWICE deliberately: the grant has to be written onto each successor row, not just read off
    // the parent — carrying it only into the minted token would lose it on the NEXT refresh.
    Lukk::abilitiesUsing(fn () => ['admin.*']);
    $rotated = rotate()($pair->refreshToken);
    expect(claims($rotated->accessToken)->scope)->toBe('ci.deploy');

    $again = rotate()($rotated->refreshToken);
    expect(claims($again->accessToken)->scope)->toBe('ci.deploy');
});

it('still derives per mint when the session pins nothing', function () {
    // The default. Keeps a revoked ability taking effect within access_ttl rather than lasting the
    // life of the refresh token — the property that makes storage OPTIONAL rather than the norm.
    Lukk::abilitiesUsing(fn () => ['orders.read', 'orders.write']);
    $pair = User::factory()->create()->startSession();

    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $rotated = rotate()($pair->refreshToken);

    expect(claims($rotated->accessToken)->scope)->toBe('orders.read');
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

    expect((array) claims($pair->accessToken))->not->toHaveKey('scope');

    Lukk::$tokenClaimsUsing = null;
});

it('does not let a claims hook forge a scope the abilities layer did not grant', function () {
    Lukk::tokenClaimsUsing(fn () => ['scope' => 'admin.*']);
    Lukk::abilitiesUsing(fn () => ['orders.read']);

    $pair = User::factory()->create()->startSession();

    expect(claims($pair->accessToken)->scope)->toBe('orders.read');

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
        ->and($seen->familyId)->toBe(claims($pair->accessToken)->fid);
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

    expect(claims(User::factory()->create()->startSession()->accessToken)->scope)
        ->toBe('orders.read orders.write');
});

it('accepts a single ability returned bare, without an array around it', function () {
    Lukk::abilitiesUsing(fn () => 'orders.read');

    expect(claims(User::factory()->create()->startSession()->accessToken)->scope)
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

it('publishes the token\'s abilities on the user resource', function () {
    // The only way a BFF-mode client can learn them: it never sees the access token that carries
    // the `scope` claim, so the user endpoint is the one channel that works in both transport modes.
    Lukk::abilitiesUsing(fn () => ['orders.read', 'billing.*']);
    Route::middleware('auth:api')->get('/_test/me', fn () => new UserResource(request()->user()));

    $this->withToken(User::factory()->create()->startSession()->accessToken)->getJson('/_test/me')
        ->assertOk()
        ->assertJsonPath('data.abilities', ['orders.read', 'billing.*']);
});

it('omits abilities entirely — rather than sending [] — when the feature is not in use', function () {
    // `[]` and absent mean different things to a client: `[]` is "granted nothing, hide the UI",
    // absent is "this server does not use abilities, show it". Sending `[]` unconditionally would
    // blank the UI of every install that upgraded without opting in.
    Route::middleware('auth:api')->get('/_test/me', fn () => new UserResource(request()->user()));

    $this->withToken(User::factory()->create()->startSession()->accessToken)->getJson('/_test/me')
        ->assertOk()
        ->assertJsonMissingPath('data.abilities');
});

it('sends an empty ability list when the feature IS in use and nothing was granted', function () {
    Lukk::abilitiesUsing(fn () => []);
    Route::middleware('auth:api')->get('/_test/me', fn () => new UserResource(request()->user()));

    $this->withToken(User::factory()->create()->startSession()->accessToken)->getJson('/_test/me')
        ->assertOk()
        ->assertJsonPath('data.abilities', []);
});

it('does not describe the reader\'s token on someone else\'s user resource', function () {
    // An admin screen listing users would otherwise stamp every row with the READER's abilities.
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $other = User::factory()->create();
    Route::middleware('auth:api')->get('/_test/other', fn () => new UserResource($other));

    // `assertSuccessful`, not `assertOk`: Laravel answers 201 for a resource wrapping a model that
    // `wasRecentlyCreated`, which `$other` is.
    $this->withToken(User::factory()->create()->startSession()->accessToken)->getJson('/_test/other')
        ->assertSuccessful()
        ->assertJsonMissingPath('data.abilities');
});

it('refuses to assume a token outside the test environment', function () {
    // A container `scoped` binding looks like it dies with the request, but
    // `forgetScopedInstances()` only drops the resolved INSTANCE — the binding, a closure holding
    // this token by value, stays registered. On Octane the next request re-resolves the same token,
    // so a leftover `actingAs` (or an impersonation feature built on it) would authorize the next
    // visitor. There is no reliable teardown hook, so it refuses to exist in production at all.
    // `local`, not `production` — flipping to production trips lukk's unrelated array-cache guard
    // first, and this test is about the environment check in `assume()`.
    app()->detectEnvironment(fn () => 'local');

    expect(fn () => Lukk::actingAs(User::factory()->create(), config('lukk.guard'), ['*']))
        ->toThrow(RuntimeException::class, 'refuses to run outside the test environment');
});

it('pins WHY that refusal is necessary: a scoped binding outlives request teardown', function () {
    // The reason `assume()` refuses in production instead of trusting the container. If this test
    // ever fails because Laravel started dropping scoped BINDINGS — not just their resolved
    // instances — the restriction can be revisited. Until then it cannot.
    Lukk::actingAs(User::factory()->create(), config('lukk.guard'), ['ci.deploy']);

    app()->forgetScopedInstances();   // what Octane runs between requests

    expect(app()->bound(VerifiedToken::class))->toBeTrue()
        ->and(app(VerifiedToken::class)[config('lukk.guard')]->abilities->all())->toBe(['ci.deploy']);
});

it('keeps a grant pinned to NOTHING pinned, instead of widening it on refresh', function () {
    // The most restricted token there is — a zero-scope PAT, an impersonation session capped to
    // nothing. `toScope()` collapses an empty grant to null and null on the column means "derive",
    // so persisting it directly handed the holder the subject's FULL grant one refresh later.
    Lukk::abilitiesUsing(fn () => ['*']);
    $pair = start()(User::factory()->create()->getKey(), [], []);

    expect((array) claims($pair->accessToken))->not->toHaveKey('scope');

    $rotated = rotate()($pair->refreshToken);
    expect((array) claims($rotated->accessToken))->not->toHaveKey('scope');

    // ...and it stays pinned across a second rotation, not just the first.
    $again = rotate()($rotated->refreshToken);
    expect((array) claims($again->accessToken))->not->toHaveKey('scope');
});

it('round-trips a pinned-empty grant as "" and never as null', function () {
    // `RefreshTokenRepository` is an advertised swap seam (DB↔Redis), and since 0.6 the `''`-vs-null
    // distinction carries a security invariant: null means "derive", `''` means "pinned to nothing".
    // Any store that coerces an empty string to NULL — a JSON/Redis codec, a DB layer with
    // `empty_string_to_null` — silently rewidens the most restricted token there is. Pin it here so
    // a replacement implementation has something to fail against.
    $repo = app(RefreshTokenRepository::class);
    $user = User::factory()->create();

    $repo->persist($user->getKey(), 'fam-pinned', null, hash('sha256', 'a'), now()->addDay()->getTimestamp(), '');
    $repo->persist($user->getKey(), 'fam-derived', null, hash('sha256', 'b'), now()->addDay()->getTimestamp(), null);

    expect(notNull($repo->findByHashForUpdate(hash('sha256', 'a')))->scope)->toBe('')
        ->and(notNull($repo->findByHashForUpdate(hash('sha256', 'b')))->scope)->toBeNull();
});

it('works on a PAT-only install that never configured a callback', function () {
    // The topology the pinned grant exists FOR: abilities come only from an explicit `StartSession`
    // grant. Every other pinning test configures `abilitiesUsing` first, so this path — the one
    // where `Lukk::$abilitiesUsing` stays null forever — was never exercised.
    config(['lukk.features.abilities' => true]);
    Route::middleware('auth:api')->get('/_test/me', fn () => new UserResource(request()->user()));

    $pair = start()(User::factory()->create()->getKey(), [], ['ci.deploy']);

    expect(claims($pair->accessToken)->scope)->toBe('ci.deploy');

    $this->withToken($pair->accessToken)->getJson('/_test/any')->assertStatus(403);
    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->getJson('/_test/me')
        ->assertJsonPath('data.abilities', ['ci.deploy']);
});

it('tells a token pinned to NOTHING from a server that does not use abilities', function () {
    // The inversion this closes: a zero-scope token carries no `scope` claim, which used to read to
    // the client as "this server has no abilities" — so the most restricted token the API can issue
    // rendered MORE privileged UI than a normal one.
    config(['lukk.features.abilities' => true]);
    Route::middleware('auth:api')->get('/_test/me', fn () => new UserResource(request()->user()));

    $pair = start()(User::factory()->create()->getKey(), [], []);

    $this->withToken($pair->accessToken)->getJson('/_test/me')
        ->assertJsonPath('data.abilities', []);   // in use, granted nothing — NOT absent
});

it('gates the ALL alias after auth too, not just the ANY one', function () {
    // `lukk.abilities` has its own priority registration; only `lukk.ability` was covered.
    Lukk::abilitiesUsing(fn () => ['orders.read', 'orders.write']);
    Route::middleware(['lukk.abilities:orders.read,orders.write', 'auth:api'])
        ->get('/_test/reordered-all', fn () => response()->json(['ok' => true]));

    $this->withToken(User::factory()->create()->startSession()->accessToken)
        ->getJson('/_test/reordered-all')->assertOk();
});

it('hands the callback the subject it is minting for', function () {
    // `TokenContext->userId` is public API and nothing asserted it — a context reporting the wrong
    // subject would let a callback grant one user's abilities to another.
    $seen = null;
    Lukk::abilitiesUsing(function ($userId, $context) use (&$seen) {
        $seen = $context->userId;

        return [];
    });

    $user = User::factory()->create();
    $user->startSession();

    expect((string) $seen)->toBe((string) $user->getKey());
});

it('records the family the token belongs to on the verified token', function () {
    // `VerifiedToken->familyId` is public API and nothing asserted it.
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $user = User::factory()->create();
    $pair = $user->startSession();

    Route::middleware('auth:api')->get('/_test/fid', fn () => response()->json([
        'fid' => VerifiedToken::current(request())?->familyId,
    ]));

    $this->withToken($pair->accessToken)->getJson('/_test/fid')
        ->assertJsonPath('fid', claims($pair->accessToken)->fid);
});

it('still logs in and rotates against a pre-0.6 schema with no scope column', function () {
    // The back-compat guard in DatabaseRefreshTokenRepository is load-bearing — without it an
    // install that upgraded the package but not the schema gets a raw SQL error on every login —
    // and it had no test.
    Schema::table('refresh_tokens', fn (Blueprint $table) => $table->dropColumn('scope'));
    Lukk::abilitiesUsing(fn () => ['orders.read']);

    $pair = User::factory()->create()->startSession();
    expect(claims($pair->accessToken)->scope)->toBe('orders.read');

    $rotated = rotate()($pair->refreshToken);
    expect(claims($rotated->accessToken)->scope)->toBe('orders.read');
});

it('honours an explicit pinned grant even with the feature flag off', function () {
    // Passing abilities to `StartSession` is unambiguous intent and must mint the claim regardless
    // — the flag only answers "should the CLIENT be told", never "should this token be scoped".
    // Server-side gating is correct here either way; forgetting the flag costs only the UI hint.
    config(['lukk.features.abilities' => false]);
    expect(Lukk::$abilitiesUsing)->toBeNull();

    $pair = start()(User::factory()->create()->getKey(), [], ['ci.deploy']);

    expect(claims($pair->accessToken)->scope)->toBe('ci.deploy');

    $this->withToken($pair->accessToken)->getJson('/_test/any')->assertStatus(403);
});

it('announces a refusal, so a token probing gates is visible', function () {
    // The only lukk-side signal that a token is being used beyond its grant — which is what a stolen
    // one probing for reachable routes looks like.
    Event::fake([TokenAbilityDenied::class]);
    Lukk::abilitiesUsing(fn () => ['users.read']);
    $pair = User::factory()->create()->startSession();

    $this->withToken($pair->accessToken)->getJson('/_test/all')->assertStatus(403);

    Event::assertDispatched(TokenAbilityDenied::class, function (TokenAbilityDenied $e) use ($pair) {
        // The ROUTE's requirement, never the caller's granted list — a queued listener serializes
        // this payload, and the caller's entitlement is not lukk's to spread further.
        return $e->required === ['orders.read', 'orders.write']
            && $e->requiresAll === true
            && $e->familyId === claims($pair->accessToken)->fid
            && ! property_exists($e, 'granted');
    });
});

it('does not announce a refusal when the token was simply absent', function () {
    // No token is a 401 — "log in" — not an authorization refusal. Firing here would drown the
    // signal that matters in ordinary logged-out traffic.
    Event::fake([TokenAbilityDenied::class]);

    $this->getJson('/_test/any')->assertStatus(401);

    Event::assertNotDispatched(TokenAbilityDenied::class);
});

it('does not announce a refusal for a caller holding no lukk token at all', function () {
    // Authenticated by other means (a session guard, `actingAs` without abilities): refused, but
    // there is no subject/guard/family to report and nothing resembling a token probing its limits.
    Event::fake([TokenAbilityDenied::class]);
    Lukk::actingAs(User::factory()->create(), config('lukk.guard'));

    $this->getJson('/_test/any')->assertStatus(403);

    Event::assertNotDispatched(TokenAbilityDenied::class);
});

it('still detects reuse when the abilities callback is throwing', function () {
    // The one direction this package must never fail. Resolving the grant before the transaction
    // put the callback ahead of every reject branch, so a replayed token ran it FIRST — and a
    // throwing callback killed the request before the reuse branch ever ran: no family revoke, no
    // event, reuse detection silently off for as long as the permission store misbehaved. A subject
    // whose derived ability names can be made malformed could switch it off deliberately.
    $this->freezeSecond();
    config(['lukk.grace_seconds' => 10]);
    Event::fake([RefreshTokenReused::class]);

    $pair = User::factory()->create()->startSession();
    rotate()($pair->refreshToken);

    Lukk::abilitiesUsing(fn () => throw new RuntimeException('permission store is down'));

    $this->travel(60)->seconds(function () use ($pair) {
        expect(fn () => rotate()($pair->refreshToken))->toThrow(InvalidRefreshToken::class, 'reuse');
    });

    Lukk::$abilitiesUsing = null;

    expect(RefreshToken::whereNull('revoked_at')->count())->toBe(0);
    Event::assertDispatched(RefreshTokenReused::class);
});

it('does not ask the permission store about a token it is going to reject', function () {
    // Unknown, revoked, expired and replayed all reject. Asking anyway turned a stolen-then-revoked
    // token into a per-request amplifier into the application's permission store, and fired any
    // side effect it carries on behalf of a session that no longer exists.
    $this->freezeSecond();
    config(['lukk.grace_seconds' => 10]);
    $user = User::factory()->create();
    $pair = $user->startSession();
    $replayed = $user->startSession();
    rotate()($replayed->refreshToken);

    revokeAll()($user->getKey());

    $calls = 0;
    Lukk::abilitiesUsing(function () use (&$calls) {
        $calls++;

        return ['orders.read'];
    });

    foreach (['revoked' => $pair->refreshToken, 'unknown' => str_repeat('f', 64)] as $secret) {
        try {
            rotate()($secret);
        } catch (Throwable) {
        }
    }

    $this->travel(60)->seconds(function () use ($replayed) {
        try {
            rotate()($replayed->refreshToken);   // past-grace replay = reuse
        } catch (Throwable) {
        }
    });

    Lukk::$abilitiesUsing = null;

    expect($calls)->toBe(0);
});

it('publishes a pinned grant to the client even with the feature flag off', function () {
    // The grant is real and per-session; the flag is global and static. Omitting the key told the
    // client "this server doesn't use abilities", so it rendered the full privileged UI for a token
    // the API refuses.
    config(['lukk.features.abilities' => false]);
    expect(Lukk::$abilitiesUsing)->toBeNull();
    Route::middleware('auth:api')->get('/_test/me', fn () => new UserResource(request()->user()));

    $pair = start()(User::factory()->create()->getKey(), [], ['orders.read']);

    $this->withToken($pair->accessToken)->getJson('/_test/me')
        ->assertJsonPath('data.abilities', ['orders.read']);
});

it('does not let a claims hook own scope when the layer is on but has no callback', function () {
    // The pinned-grant-only topology the feature flag exists for. `abilitiesFor` returned null
    // there, which the issuer reads as "abilities not in use" — so it skipped the reservation and a
    // decorative `tokenClaimsUsing` scope was signed and honoured by the gates. The claims hook had
    // become the authorization layer.
    config(['lukk.features.abilities' => true]);
    expect(Lukk::$abilitiesUsing)->toBeNull();
    Lukk::tokenClaimsUsing(fn () => ['scope' => 'orders.read admin.*']);

    $pair = User::factory()->create()->startSession();
    Lukk::$tokenClaimsUsing = null;

    expect((array) claims($pair->accessToken))->not->toHaveKey('scope');
    $this->withToken($pair->accessToken)->getJson('/_test/any')->assertStatus(403);
});

it('fails a malformed route requirement for everyone, not only the denied', function () {
    // Validating while building the challenge header meant a route-definition typo threw only for
    // callers being REFUSED: the happy path stayed green, so the bug first appeared in production,
    // as a 500, to exactly the users already being told no.
    Lukk::abilitiesUsing(fn () => ['admin.all']);
    Route::middleware(['auth:api', 'lukk.ability:orders read'])
        ->get('/_test/typo', fn () => response()->json(['ok' => true]));

    $this->withoutExceptionHandling()
        ->withToken(User::factory()->create()->startSession()->accessToken);

    // `admin.all` satisfies nothing here, but the point is that the AUTHORIZED path throws too.
    expect(fn () => $this->getJson('/_test/typo'))
        ->toThrow(InvalidArgumentException::class, 'not a valid scope token');
});

it('gates on the authenticated subject, not merely on whatever token the request carries', function () {
    // Picking the token by guard alone never checked that its subject was the user the route
    // authenticated — so in an app where something else resolves lukk's guard in passing (telemetry,
    // a log-context middleware) the gate could authorize one user's request with another's token.
    // It also made the middleware and `$user->tokenCan()` answer differently for the same ability in
    // the same request; going through `forUser` is what makes them agree by construction.
    Lukk::abilitiesUsing(fn ($id) => $id === 2 ? ['orders.read', 'orders.write'] : []);

    $alice = User::factory()->create();                      // id 1 — granted nothing
    $bob = User::factory()->create();                        // id 2 — granted both
    $bobToken = $bob->startSession()->accessToken;

    Route::middleware(['auth:api', 'lukk.ability:orders.read'])
        ->get('/_test/subject', fn () => response()->json(['ok' => true]));

    // Bob's verified token is on the request, but Alice is the authenticated user.
    $request = request();
    VerifiedToken::put($request, new VerifiedToken(
        guard: config('lukk.guard'),
        userId: $bob->getKey(),
        userClass: $bob::class,
        familyId: 'bob-family',
        abilities: Abilities::fromScope('orders.read orders.write'),
        claims: (object) ['sub' => (string) $bob->getKey(), 'scope' => 'orders.read orders.write'],
    ));

    expect(VerifiedToken::current($request)?->userId)->toBe($bob->getKey())
        ->and(VerifiedToken::forUser($request, $alice))->toBeNull();
});

it('refuses a request whose token belongs to someone other than the authenticated user', function () {
    // The enforcement path, not just the helper. A lukk token is recorded on the request while a
    // DIFFERENT user is the one the route authenticated — the shape an app produces when something
    // resolves lukk's guard in passing (telemetry, a log-context middleware) on a session-guarded
    // route. Picking the token by guard alone authorized Alice's request with Bob's grant.
    $alice = User::factory()->create();
    $bob = User::factory()->create();

    Lukk::actingAs($bob, config('lukk.guard'), ['orders.read', 'orders.write']);
    $this->be($alice, 'web');   // ...but the ROUTE authenticates Alice, on another guard

    Route::middleware(['auth:web', 'lukk.ability:orders.read'])
        ->get('/_test/subject-gate', fn () => response()->json([
            'acting_as' => actor()->getKey(),
            'token_can' => actor()->tokenCan('orders.read'),
        ]));

    // Must deny — and must agree with `tokenCan()`, which has always said false for Alice.
    $this->getJson('/_test/subject-gate')->assertStatus(403);
});

it('refuses to let a pinned token log the account out everywhere', function () {
    // The contradiction this closes: a token pinned to one ability — the most restricted thing the
    // API can issue, refused by every gated route in the application — could still revoke every
    // OTHER session, because lukk's own routes were gated on authentication alone.
    $user = User::factory()->create();
    $human = $user->startSession();
    $pat = start()($user->getKey(), [], ['ci.deploy']);

    $this->withToken($pat->accessToken)->deleteJson('/auth/sessions')->assertStatus(403);
    app('auth')->forgetGuards();

    // ...and the human session it tried to kill is still alive.
    $this->withToken($human->accessToken)->postJson('/auth/logout')->assertSuccessful();
});

it('lets a pinned token that asked for it manage sessions', function () {
    $user = User::factory()->create();
    $pat = start()($user->getKey(), [], ['ci.deploy', 'lukk.sessions']);

    $this->withToken($pat->accessToken)->deleteJson('/auth/sessions')->assertSuccessful();
});

it('never gates an ordinary session, with or without abilities configured', function () {
    // A derived grant is a live human login. Gating it would break every working install on
    // upgrade, and would make people hunt for an ability name to get logout-all back.
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $withAbilities = User::factory()->create()->startSession();
    $this->withToken($withAbilities->accessToken)->deleteJson('/auth/sessions')->assertSuccessful();

    Lukk::$abilitiesUsing = null;
    app('auth')->forgetGuards();

    $plain = User::factory()->create()->startSession();
    expect((array) claims($plain->accessToken))->not->toHaveKey('pin');
    $this->withToken($plain->accessToken)->deleteJson('/auth/sessions')->assertSuccessful();
});

it('still lets a pinned token end and renew its OWN session', function () {
    // `logout` and `refresh` act on the calling session alone — a PAT has to be able to end and
    // renew itself, or pinning a grant would make the token unusable rather than restricted.
    $user = User::factory()->create();
    $pat = start()($user->getKey(), [], ['ci.deploy']);

    $rotated = rotate()($pat->refreshToken);
    expect(claims($rotated->accessToken)->scope)->toBe('ci.deploy')
        ->and(claims($rotated->accessToken)->pin)->toBeTrue();

    app('auth')->forgetGuards();
    $this->withToken($rotated->accessToken)->postJson('/auth/logout')->assertSuccessful();
});

it('marks only a pinned grant with the pin claim', function () {
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $derived = User::factory()->create()->startSession();
    $pinned = start()(User::factory()->create()->getKey(), [], ['orders.read']);

    expect((array) claims($derived->accessToken))->not->toHaveKey('pin')
        ->and(claims($pinned->accessToken)->pin)->toBeTrue();
});

it('restores the old behaviour when the route gate is switched off', function () {
    // The escape hatch: an install that relies on a pinned token doing session management, or that
    // wants lukk's routes gated only by its own middleware, turns the whole thing off.
    config(['lukk.features.gate_auth_routes' => false]);
    $user = User::factory()->create();
    $pat = start()($user->getKey(), [], ['ci.deploy']);

    $this->withToken($pat->accessToken)->deleteJson('/auth/sessions')->assertSuccessful();
});

it('does not let a claims hook mark an ordinary session as a machine token', function () {
    // `pin` is reserved like `scope`, and unset unconditionally rather than merged: a standard claim
    // only wins the merge where it HAS a key, and `pin` is absent for a derived token — so a hook
    // could stamp it on a real user's session and lukk would then refuse them session management.
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    Lukk::tokenClaimsUsing(fn () => ['pin' => true]);

    $pair = User::factory()->create()->startSession();
    Lukk::$tokenClaimsUsing = null;

    expect((array) claims($pair->accessToken))->not->toHaveKey('pin');
    $this->withToken($pair->accessToken)->deleteJson('/auth/sessions')->assertSuccessful();
});

it('does not let a claims hook strip the pin off a machine token', function () {
    // The escalation direction: suppressing `pin` would hand a pinned token session management back.
    Lukk::tokenClaimsUsing(fn () => ['pin' => false]);

    $pat = start()(User::factory()->create()->getKey(), [], ['ci.deploy']);
    Lukk::$tokenClaimsUsing = null;

    expect(claims($pat->accessToken)->pin)->toBeTrue();
    $this->withToken($pat->accessToken)->deleteJson('/auth/sessions')->assertStatus(403);
});

it('sorts the session gate after authentication, whatever order a route declares', function () {
    // The gate reads the authenticated user, so running before `Authenticate` would leave it with
    // null and make it a silent no-op — the whole gate bypassed. `Authenticate` is in the kernel's
    // priority list, so declaration order alone does not decide this.
    Route::middleware([RequirePinnedAbility::class.':'.Abilities::SESSIONS, 'auth:api'])
        ->delete('/_test/gate-order', fn () => response()->json(['ok' => true]));

    $pat = start()(User::factory()->create()->getKey(), [], ['ci.deploy']);

    $this->withToken($pat->accessToken)->deleteJson('/_test/gate-order')->assertStatus(403);
});

it('lets actingAs stand in for a PINNED token, so the session gate is testable', function () {
    // Passing an explicit ability list to `actingAs` IS the pinned semantic. Without the `pin` mark
    // a consumer could not write a passing test for "my narrowly-scoped token must not revoke
    // sessions" using lukk's own helper — the gate waved it through and the test read as a bug.
    Lukk::actingAs(User::factory()->create(), config('lukk.guard'), ['ci.deploy']);

    $this->deleteJson('/auth/sessions')->assertStatus(403);
});

it('tells the client abilities are in use for a token pinned to nothing', function () {
    // The last gap in the absent-vs-empty signal: a zero-scope token carries no `scope` claim, so
    // with the flag off it reported no `abilities` key — which the client reads as "this server
    // doesn't use abilities" and renders the full privileged UI for. `pin` makes it detectable.
    config(['lukk.features.abilities' => false]);
    Route::middleware('auth:api')->get('/_test/me', fn () => new UserResource(request()->user()));

    $pair = start()(User::factory()->create()->getKey(), [], []);

    $this->withToken($pair->accessToken)->getJson('/_test/me')
        ->assertJsonPath('data.abilities', []);
});

it('resolves the claims hook outside the refresh transaction, like the abilities one', function () {
    // Moving the mint inside the transaction left `tokenClaimsUsing` under the row lock, because the
    // issuer resolved it. Same consumer callback, same permission-store read, same hazards.
    $levels = [];
    Lukk::tokenClaimsUsing(function () use (&$levels) {
        $levels[] = DB::transactionLevel();

        return ['org' => 1];
    });

    $baseline = DB::transactionLevel();
    $pair = User::factory()->create()->startSession();
    $rotated = rotate()($pair->refreshToken);
    Lukk::$tokenClaimsUsing = null;

    expect($levels)->each->toBe($baseline)
        // ...and the hook's claims still reach the token, on both mint paths.
        ->and(claims($pair->accessToken)->org)->toBe(1)
        ->and(claims($rotated->accessToken)->org)->toBe(1);
});

it('does not ask the claims hook about a token it is going to reject', function () {
    // Same reject short-circuit abilities use: a throwing hook must not be able to pre-empt reuse
    // detection, and a replayed token must not drive the application's permission store.
    $this->freezeSecond();
    config(['lukk.grace_seconds' => 10]);
    $user = User::factory()->create();
    $replayed = $user->startSession();
    rotate()($replayed->refreshToken);

    $calls = 0;
    Lukk::tokenClaimsUsing(function () use (&$calls) {
        $calls++;

        return [];
    });

    $this->travel(60)->seconds(function () use ($replayed) {
        try {
            rotate()($replayed->refreshToken);
        } catch (Throwable) {
        }
    });

    Lukk::$tokenClaimsUsing = null;
    expect($calls)->toBe(0);
});

it('keeps per-login claims winning over the hook, now that the Action merges them', function () {
    // Precedence used to live in the issuer's `array_merge($custom, $claims, $standard)`. Hoisting
    // the hook moved that ordering into the Action, where nothing was asserting it — a silent
    // inversion would let a global hook override a value the login path deliberately set.
    Lukk::tokenClaimsUsing(fn () => ['org' => 'from-hook', 'only_hook' => true]);

    $pair = start()(User::factory()->create()->getKey(), ['org' => 'from-login']);
    Lukk::$tokenClaimsUsing = null;

    $claims = claims($pair->accessToken);

    expect($claims->org)->toBe('from-login')
        ->and($claims->only_hook)->toBeTrue()
        // ...and standard claims still beat both.
        ->and($claims->iss)->toBe(config('lukk.issuer'));
});

it('refuses a pinned token the step-up gateway, and what it unlocks', function () {
    // Step-up leads to enrolling a passkey, disabling two-factor, regenerating recovery codes. All
    // of it needs the password, so a pinned token could never do it silently — but "a machine token
    // must not log the account out everywhere" and "a machine token may enrol a permanent
    // authenticator" cannot both be the rule.
    $user = User::factory()->create(['password' => Hash::make('secret-shim')]);
    $pat = start()($user->getKey(), [], ['ci.deploy']);

    $this->withToken($pat->accessToken)
        ->postJson('/auth/confirm-password', ['password' => 'secret-shim'])
        ->assertStatus(403);
});

it('refuses a pinned token the password change, which is takeover plus a session sweep', function () {
    $user = User::factory()->create(['password' => Hash::make('secret-shim')]);
    $pat = start()($user->getKey(), [], ['ci.deploy']);

    $this->withToken($pat->accessToken)->postJson('/auth/password', [
        'current_password' => 'secret-shim',
        'password' => 'a-brand-new-secret',
        'password_confirmation' => 'a-brand-new-secret',
    ])->assertStatus(403);
});

it('lets a pinned token that asked for lukk.account step up', function () {
    $user = User::factory()->create(['password' => Hash::make('secret-shim')]);
    $pat = start()($user->getKey(), [], ['ci.deploy', Abilities::ACCOUNT]);

    $this->withToken($pat->accessToken)
        ->postJson('/auth/confirm-password', ['password' => 'secret-shim'])
        ->assertSuccessful();
});

it('never gates an ordinary session out of step-up or a password change', function () {
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $user = User::factory()->create(['password' => Hash::make('secret-shim')]);

    $this->withToken($user->startSession()->accessToken)
        ->postJson('/auth/confirm-password', ['password' => 'secret-shim'])
        ->assertSuccessful();
});

it('falls back to the database when a custom issuer forgets to stamp the pin claim', function () {
    // `pin` is stamped by `TokenIssuer`, a documented swap seam. An implementation that forwards
    // `$abilities` but drops `TokenContext::$pinned` yields a genuinely pinned token with no claim —
    // and a claim-only check waves it through. Note the asymmetry that makes this worth a round
    // trip: the `scope` half of the same seam fails CLOSED and loudly, this half failed OPEN and
    // silently, so the install looks healthy while the control is gone.
    $user = User::factory()->create();
    $pat = start()($user->getKey(), [], ['ci.deploy']);

    // Re-mint the same session's access token with the pin deliberately dropped.
    $forgetful = app(TokenIssuer::class)->accessToken(
        new TokenContext(config('lukk.guard'), $user->getKey(), claims($pat->accessToken)->fid),
        abilities: Abilities::fromArray(['ci.deploy']),
    );

    expect((array) claims($forgetful['token']))->not->toHaveKey('pin');

    $this->withToken($forgetful['token'])->deleteJson('/auth/sessions')->assertStatus(403);
});

it('does not break logout-all on a pre-0.6 schema with no scope column', function () {
    // The authoritative pinned lookup queries `scope`, which an install that upgraded the package
    // but not the schema does not have — and this path runs for ORDINARY logouts, so a hard failure
    // here would break every such install. Nothing there can be pinned, so nothing there can be
    // wrongly ungated: answer false rather than probing the schema on every call.
    Schema::table('refresh_tokens', fn (Blueprint $table) => $table->dropColumn('scope'));

    $user = User::factory()->create();
    $pair = $user->startSession();

    expect(app(RefreshTokenRepository::class)->familyIsPinned(claims($pair->accessToken)->fid))
        ->toBeFalse();

    $this->withToken($pair->accessToken)->deleteJson('/auth/sessions')->assertSuccessful();
});

it('refuses a pinned token the passkey step-up path too', function () {
    // `confirm-passkey` is the OTHER way to reach step-up. Gating only the password path would make
    // the gate decorative for any account with a passkey enrolled.
    $user = User::factory()->create();
    $pat = start()($user->getKey(), [], ['ci.deploy']);

    $this->withToken($pat->accessToken)
        ->postJson('/auth/confirm-passkey', ['id' => 'x', 'rawId' => 'x', 'type' => 'public-key', 'response' => []])
        ->assertStatus(403);
});

it('tells the client whether its own session is a machine token', function () {
    // `abilities` alone is the wrong predictor for lukk's own gated routes, which apply to pinned
    // tokens only: a normal user's derived grant never contains `lukk.sessions`, so a client gating
    // "sign out other devices" on it would hide the button from everyone.
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    Route::middleware('auth:api')->get('/_test/me', fn () => new UserResource(request()->user()));

    $human = User::factory()->create()->startSession();
    $this->withToken($human->accessToken)->getJson('/_test/me')
        ->assertJsonPath('data.token_pinned', false);

    app('auth')->forgetGuards();

    $pat = start()(User::factory()->create()->getKey(), [], ['ci.deploy']);
    $this->withToken($pat->accessToken)->getJson('/_test/me')
        ->assertJsonPath('data.token_pinned', true);
});

it('refuses a pinned token the security metadata behind lukk.account', function () {
    // The reads of the same objects the write side protects: credential ids, human-chosen device
    // names, last-use timestamps, and how many recovery codes remain — reconnaissance for the same
    // attack, and `lukk.account`'s docblock already claimed to cover those objects.
    config(['lukk.features.two_factor' => true]);
    $pat = start()(User::factory()->create()->getKey(), [], ['ci.deploy']);

    $this->withToken($pat->accessToken)->getJson('/auth/two-factor/recovery-codes')->assertStatus(403);
});

it('accepts a comma-separated list on the pinned gate, meaning ANY of them', function () {
    // A single non-variadic parameter silently dropped everything after the first — the same syntax
    // that means ANY-of one line above in the routes file.
    Route::middleware(['auth:api', RequirePinnedAbility::class.':'.Abilities::SESSIONS.','.Abilities::ACCOUNT])
        ->get('/_test/any-pinned', fn () => response()->json(['ok' => true]));

    $pat = start()(User::factory()->create()->getKey(), [], ['ci.deploy', Abilities::ACCOUNT]);

    $this->withToken($pat->accessToken)->getJson('/_test/any-pinned')->assertOk();
});

it('fails a parameterless pinned gate loudly, for everyone', function () {
    // It was an ArgumentCountError — a 500 for ordinary users too, where the sibling gate turns the
    // same route-definition mistake into a diagnosable exception.
    Route::middleware(['auth:api', RequirePinnedAbility::class])
        ->get('/_test/no-param', fn () => response()->json(['ok' => true]));

    $this->withoutExceptionHandling()
        ->withToken(User::factory()->create()->startSession()->accessToken);

    expect(fn () => $this->getJson('/_test/no-param'))
        ->toThrow(InvalidArgumentException::class, 'needs at least one ability');
});

it('refuses to mint a pinned session whose pin did not reach storage', function () {
    // The escalation this closes, reproduced end to end before the fix: a `useRefreshTokenModel`
    // subclass declaring `$fillable` silently dropped `scope` from the mass-assigned insert, so a
    // token pinned to `['ci.deploy']` came back as the subject's FULL derived grant one refresh
    // later — and regained session management with it, because `familyIsPinned()` reads the same
    // column that was never written. Both halves of the defence collapsed together.
    // A custom repository is free to ignore `$scope`; it is not free to let lukk hand back a token
    // whose restriction it discarded. (The model seam can no longer cause this — `persist` force
    // fills — so the remaining route is a repository that drops the argument.)
    app()->bind(RefreshTokenRepository::class, fn () => new class extends DatabaseRefreshTokenRepository
    {
        public function persist(int|string $userId, string $familyId, ?string $previousId, string $tokenHash, int $expiresAt, ?string $scope = null): void
        {
            parent::persist($userId, $familyId, $previousId, $tokenHash, $expiresAt);
        }
    });
    Lukk::abilitiesUsing(fn () => ['admin.everything']);

    expect(fn () => start()(User::factory()->create()->getKey(), [], ['ci.deploy']))
        ->toThrow(RuntimeException::class, 'could not store this session\'s pinned abilities');
});

it('persists a pinned grant through a model that filters mass assignment', function () {
    // The fix itself: these attributes are lukk's own, so the consumer's assignment policy has no
    // business filtering them.
    Lukk::useRefreshTokenModel(FillableRefreshToken::class);
    Lukk::abilitiesUsing(fn () => ['admin.everything']);

    $pat = start()(User::factory()->create()->getKey(), [], ['ci.deploy']);
    $rotated = rotate()($pat->refreshToken);

    expect(claims($rotated->accessToken)->scope)->toBe('ci.deploy')
        ->and(claims($rotated->accessToken)->pin)->toBeTrue();

    Lukk::$refreshTokenModel = null;
});

it('leaves no orphan refresh row when the permission store is down at login', function () {
    // `StartSession` used to evaluate the consumer callbacks as ARGUMENTS to `accessToken()`, i.e.
    // after the insert — so a throwing permission store left live rows whose secret was never
    // delivered to anyone, inflating the family fan-out signal along the way.
    Lukk::abilitiesUsing(fn () => throw new RuntimeException('permission store down'));
    $user = User::factory()->create();

    foreach (range(1, 3) as $ignored) {
        try {
            $user->startSession();
        } catch (Throwable) {
        }
    }

    Lukk::$abilitiesUsing = null;

    expect(RefreshToken::count())->toBe(0);
});

/** A consumer model that filters mass assignment — `useRefreshTokenModel` is a documented seam. */
class FillableRefreshToken extends RefreshToken
{
    protected $table = 'refresh_tokens';

    protected $fillable = ['user_id', 'family_id', 'previous_id', 'token_hash', 'expires_at', 'guard'];
}
