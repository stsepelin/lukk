<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Cache\Events\ForgettingKey;
use Illuminate\Cache\Events\RetrievingKey;
use Illuminate\Cache\Events\WritingKey;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Lukk\Actions\ClaimSession;
use Lukk\Actions\RevokeSession;
use Lukk\Actions\StartSession;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Events\RefreshTokenReused;
use Lukk\Events\SessionUnclaimed;
use Lukk\Models\RefreshToken;
use Lukk\Refresh\DatabaseRefreshTokenRepository;
use Lukk\Support\RefreshTokenRecord;
use Lukk\Support\UnclaimedSessions;
use Lukk\Tests\Fixtures\User;

// Unclaimed sessions (opt-in, `claim_seconds`). A session whose sign-in response never reached the
// client — a dropped connection, an aborted request — is never used by that client, yet lived on until
// its refresh token expired. With a window set, a new session must be USED within it; its first use
// after the window revokes the whole family instead.
uses()->group('refresh');

beforeEach(function () {
    $this->freezeSecond();

    // The effective window is at least access_ttl + leeway (see the clamp tests below), so a short
    // access TTL keeps a `claim_seconds` of 600 meaning 600 in the tests that are not about the clamp.
    config(['lukk.access_ttl' => 300]);

    resetMissingOriginWarning();
});

// The unrecognisable-original warning is once per process, so its flag is static: reset it around EVERY test,
// so a failed assertion in one cannot leak a set flag into the next.
afterEach(fn () => resetMissingOriginWarning());

function resetMissingOriginWarning(): void
{
    (new ReflectionProperty(ClaimSession::class, 'warnedMissingOrigin'))->setValue(null, false);
}

/**
 * Replace the repository with one that reports only the signals asked for — a replacement written
 * against an older version of the contract, or a careless one.
 */
function bindRepositoryReporting(bool $original, bool $createdAt): void
{
    app()->bind(RefreshTokenRepository::class, fn () => new class($original, $createdAt) extends DatabaseRefreshTokenRepository
    {
        public function __construct(private readonly bool $reportsOriginal, private readonly bool $reportsCreatedAt)
        {
            parent::__construct();
        }

        public function findByHash(string $hash): ?RefreshTokenRecord
        {
            $r = parent::findByHash($hash);

            return $r === null ? null : new RefreshTokenRecord(
                $r->id, $r->userId, $r->familyId, $r->rotatedAt, $r->revokedAt, $r->expiresAt, $r->scope,
                createdAt: $this->reportsCreatedAt ? $r->createdAt : null,
                original: $this->reportsOriginal ? $r->original : null,
            );
        }
    });
}

/**
 * Every cache operation on an unclaimed-session key, as `op:familyId`.
 *
 * @return ArrayObject<int, string>
 */
function claimCacheOps(): ArrayObject
{
    $ops = new ArrayObject;
    $record = function (string $op) use ($ops) {
        return function ($event) use ($op, $ops) {
            if (str_starts_with((string) $event->key, 'lukk:unclaimed:')) {
                $ops[] = $op.':'.substr((string) $event->key, strlen('lukk:unclaimed:'));
            }
        };
    };

    Event::listen(RetrievingKey::class, $record('read'));
    Event::listen(WritingKey::class, $record('write'));
    Event::listen(ForgettingKey::class, $record('forget'));

    return $ops;
}

function signIn(User $user): array
{
    return test()->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->assertOk()->json();
}

function familyFor(string $refreshToken): string
{
    return (string) RefreshToken::where('token_hash', hash('sha256', $refreshToken))->value('family_id');
}

function isUnclaimed(string $familyId): bool
{
    return Cache::has('lukk:unclaimed:'.$familyId);
}

/** A second request in the same test, as a fresh request would see it. */
function freshRequest(): void
{
    app('auth')->forgetGuards();
}

it('touches no unclaimed-session state at all when the feature is off', function () {
    // The default. Every authenticated request passes through this code, so "off" has to cost nothing.
    $ops = claimCacheOps();
    Event::fake([SessionUnclaimed::class]);
    $user = User::factory()->create();

    // Not even resolved: the guard's hot path is an integer compare, not a call into an action that
    // then decides to do nothing.
    $resolved = 0;
    app()->resolving(ClaimSession::class, function () use (&$resolved) {
        $resolved++;
    });
    app()->resolving(UnclaimedSessions::class, function () use (&$resolved) {
        $resolved++;
    });

    $tokens = signIn($user);
    freshRequest();
    $this->withToken($tokens['access_token'])->postJson('/auth/session/claim')->assertNoContent();
    $rotated = $this->postJson('/auth/refresh', ['refresh_token' => $tokens['refresh_token']])->assertOk()->json();
    freshRequest();
    $this->withToken($rotated['access_token'])->postJson('/auth/logout')->assertNoContent();

    expect($ops->getArrayCopy())->toBe([])
        ->and($resolved)->toBe(0);
    Event::assertNotDispatched(SessionUnclaimed::class);
});

it('marks a session started by a sign-in as unclaimed', function () {
    config(['lukk.claim_seconds' => 600]);
    $tokens = signIn(User::factory()->create());

    $family = familyFor($tokens['refresh_token']);

    expect(isUnclaimed($family))->toBeTrue()
        ->and(Cache::get('lukk:unclaimed:'.$family))->toBe(now()->getTimestamp());
});

it('marks a session started by registration too — StartSession is the one place families are born', function () {
    config(['lukk.claim_seconds' => 600]);

    $refresh = $this->postJson('/auth/register', [
        'name' => 'New', 'email' => 'new@example.test', 'password' => 'password-123', 'password_confirmation' => 'password-123',
    ])->assertOk()->json('refresh_token');

    expect(isUnclaimed(familyFor($refresh)))->toBeTrue();
});

it('never marks a pinned session, whose first use is legitimately far from its issue', function () {
    // A personal access token or an impersonation session is handed to a person or a machine that
    // uses it when it needs to — possibly days later. It was delivered by the application, not by a
    // sign-in response that can be lost, so there is nothing to claim.
    config(['lukk.claim_seconds' => 600]);
    $user = User::factory()->create();

    $pair = app(StartSession::class)($user->getKey(), [], ['orders.read']);

    expect(isUnclaimed(familyFor($pair->refreshToken)))->toBeFalse();
});

it('claims on the first authenticated request, then costs one cache read per request', function () {
    config(['lukk.claim_seconds' => 600]);
    Route::middleware('auth:api')->get('/_test/claim-me', fn () => ['id' => actor()->getAuthIdentifier()]);
    $user = User::factory()->create();
    $tokens = signIn($user);
    $family = familyFor($tokens['refresh_token']);
    $ops = claimCacheOps();

    freshRequest();
    $this->withToken($tokens['access_token'])->getJson('/_test/claim-me')->assertOk();

    expect($ops->getArrayCopy())->toBe(['read:'.$family, 'forget:'.$family])
        ->and(isUnclaimed($family))->toBeFalse();

    $ops->exchangeArray([]);
    freshRequest();
    $this->withToken($tokens['access_token'])->getJson('/_test/claim-me')->assertOk();

    expect($ops->getArrayCopy())->toBe(['read:'.$family]);
});

it('claims on a refresh inside the window', function () {
    config(['lukk.claim_seconds' => 600]);
    $tokens = signIn(User::factory()->create());
    $family = familyFor($tokens['refresh_token']);

    $rotated = $this->postJson('/auth/refresh', ['refresh_token' => $tokens['refresh_token']])->assertOk()->json();

    expect(isUnclaimed($family))->toBeFalse();

    // Long after the window, the claimed session carries on.
    $this->travel(3600)->seconds();
    $this->postJson('/auth/refresh', ['refresh_token' => $rotated['refresh_token']])->assertOk();
});

it('answers the claim route with a bare 204 and claims the session', function () {
    config(['lukk.claim_seconds' => 600]);
    $tokens = signIn(User::factory()->create());

    freshRequest();
    $response = $this->withToken($tokens['access_token'])->postJson('/auth/session/claim')->assertNoContent();

    expect($response->getContent())->toBe('')
        ->and(isUnclaimed(familyFor($tokens['refresh_token'])))->toBeFalse();
});

it('requires authentication for the claim route', function () {
    $this->postJson('/auth/session/claim')->assertUnauthorized();
});

it('does not gate the claim route on a pinned grant', function () {
    // It acts on the calling session alone, like logout and refresh — a pinned token must be able to
    // do what every other token does, and it grants nothing.
    $user = User::factory()->create();
    $pair = app(StartSession::class)($user->getKey(), [], ['orders.read']);

    $this->withToken($pair->accessToken)->postJson('/auth/session/claim')->assertNoContent();
});

it('revokes the whole family and answers 401 when the first use is an access token after the window', function () {
    config(['lukk.claim_seconds' => 600]);
    Event::fake([SessionUnclaimed::class, RefreshTokenReused::class]);
    $tokens = signIn(User::factory()->create());
    $family = familyFor($tokens['refresh_token']);

    $this->travel(601)->seconds();

    freshRequest();
    $this->withToken($tokens['access_token'])->postJson('/auth/session/claim')->assertUnauthorized();

    expect(RefreshToken::where('family_id', $family)->whereNull('revoked_at')->exists())->toBeFalse()
        ->and(app(Denylist::class)->has('fid', $family))->toBeTrue()
        ->and(isUnclaimed($family))->toBeFalse();

    // Not reuse: nothing was replayed.
    Event::assertDispatched(SessionUnclaimed::class, fn ($e) => $e->familyId === $family && $e->guard === 'api');
    Event::assertNotDispatched(RefreshTokenReused::class);

    $this->postJson('/auth/refresh', ['refresh_token' => $tokens['refresh_token']])->assertUnauthorized();
});

it('revokes the whole family and rejects when the first use is a refresh after the window', function () {
    config(['lukk.claim_seconds' => 600]);
    Event::fake([SessionUnclaimed::class, RefreshTokenReused::class]);
    $tokens = signIn(User::factory()->create());
    $family = familyFor($tokens['refresh_token']);

    $this->travel(601)->seconds();

    $this->postJson('/auth/refresh', ['refresh_token' => $tokens['refresh_token']])->assertUnauthorized();

    expect(RefreshToken::where('family_id', $family)->count())->toBe(1)   // nothing minted
        ->and(RefreshToken::where('family_id', $family)->whereNull('revoked_at')->exists())->toBeFalse()
        ->and(app(Denylist::class)->has('fid', $family))->toBeTrue();

    Event::assertDispatched(SessionUnclaimed::class);
    Event::assertNotDispatched(RefreshTokenReused::class);
});

it('still accepts a first use at exactly the end of the window', function () {
    config(['lukk.claim_seconds' => 600]);
    $tokens = signIn(User::factory()->create());

    $this->travel(600)->seconds();

    freshRequest();
    $this->withToken($tokens['access_token'])->postJson('/auth/session/claim')->assertNoContent();
});

it('fails open when the cache evicts the marker — the session is treated as claimed', function () {
    // A marker the cache no longer holds cannot be told apart from a claimed session. Failing CLOSED
    // would log out every session whose marker a cache flush or eviction dropped; failing open costs
    // only the cleanup this feature adds.
    config(['lukk.claim_seconds' => 600]);
    $tokens = signIn(User::factory()->create());
    $family = familyFor($tokens['refresh_token']);

    Cache::forget('lukk:unclaimed:'.$family);
    $this->travel(601)->seconds();

    freshRequest();
    $this->withToken($tokens['access_token'])->postJson('/auth/session/claim')->assertNoContent();
    expect(RefreshToken::where('family_id', $family)->whereNull('revoked_at')->exists())->toBeTrue();
});

it('removes the marker when an unclaimed session is logged out', function () {
    config(['lukk.claim_seconds' => 600]);
    $tokens = signIn(User::factory()->create());
    $family = familyFor($tokens['refresh_token']);

    $this->postJson('/auth/logout', ['refresh_token' => $tokens['refresh_token']])->assertNoContent();

    expect(isUnclaimed($family))->toBeFalse()
        ->and(RefreshToken::where('family_id', $family)->whereNull('revoked_at')->exists())->toBeFalse();
});

it('treats a non-numeric or negative window as off', function (mixed $window) {
    config(['lukk.claim_seconds' => $window]);
    $tokens = signIn(User::factory()->create());

    expect(isUnclaimed(familyFor($tokens['refresh_token'])))->toBeFalse();
})->with(['not-a-number', -5, null]);

it('re-checks its own off switch, which is `window <= 0` and not one second more', function () {
    // Neither caller reaches the action with a window it should ignore — `JwtGuard` compares an integer
    // first and `RotateRefreshToken` is handed null — and `UnclaimedSessions::window()` only ever
    // answers 0 or a value clamped to at least 60. So this switch is only reachable by constructing the
    // action, which is what a consumer rebinding `ClaimSession` does. Off must cost nothing at all, and
    // must not quietly swallow a window that was asked for.
    config(['lukk.claim_seconds' => 600]);
    $tokens = signIn(User::factory()->create());
    $family = familyFor($tokens['refresh_token']);
    $issuedAt = Cache::get('lukk:unclaimed:'.$family);

    $claim = fn (int $window) => new ClaimSession(app(UnclaimedSessions::class), app(RevokeSession::class), $window);

    $ops = claimCacheOps();

    expect($claim(0)($family, $issuedAt))->toBeTrue()
        ->and($claim(-1)($family, $issuedAt))->toBeTrue()
        ->and($ops->getArrayCopy())->toBe([]);   // not even the one cache read

    // On, at the smallest window there is: a first use two seconds after a one-second window is late.
    $this->travel(2)->seconds();

    expect($claim(1)($family, $issuedAt, original: true))->toBeFalse()
        ->and(RefreshToken::where('family_id', $family)->whereNull('revoked_at')->exists())->toBeFalse();
});

it('throttles the claim route per user, not per address', function () {
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);
    $first = User::factory()->create()->startSession();
    $second = User::factory()->create()->startSession();

    $this->withToken($first->accessToken)->postJson('/auth/session/claim')->assertNoContent();
    freshRequest();
    $this->withToken($first->accessToken)->postJson('/auth/session/claim')->assertStatus(429);

    // Another user behind the same address is unaffected.
    freshRequest();
    $this->withToken($second->accessToken)->postJson('/auth/session/claim')->assertNoContent();
});

// ---------------------------------------------------------------------------
// Only the sign-in's ORIGINAL credential is ever revoked. A client that uses its access token only on
// another service never claims here, and a lost marker delete (a cache restored from a snapshot, a
// failover) can resurrect a marker for a session in active use. Neither may log that session out.
// ---------------------------------------------------------------------------

it('never revokes a refreshed session whose marker came back, when it presents its rotated refresh token', function () {
    config(['lukk.claim_seconds' => 600]);
    $tokens = signIn(User::factory()->create());
    $family = familyFor($tokens['refresh_token']);
    $issuedAt = Cache::get('lukk:unclaimed:'.$family);

    $this->travel(10)->seconds();
    $rotated = $this->postJson('/auth/refresh', ['refresh_token' => $tokens['refresh_token']])->assertOk()->json();
    expect(isUnclaimed($family))->toBeFalse();

    // The claim's delete is lost: the cache is restored from a snapshot taken before it.
    Cache::put('lukk:unclaimed:'.$family, $issuedAt, 3600);
    $this->travel(700)->seconds();

    $this->postJson('/auth/refresh', ['refresh_token' => $rotated['refresh_token']])->assertOk();

    expect(RefreshToken::where('family_id', $family)->whereNull('revoked_at')->exists())->toBeTrue()
        ->and(isUnclaimed($family))->toBeFalse();
});

it('never revokes a refreshed session whose marker came back, when it presents a later access token', function () {
    config(['lukk.claim_seconds' => 600]);
    // Signed in 20 s ago (a travelled clock), refreshed NOW — firebase checks `iat` on real time, so
    // the refreshed access token has to be minted at the real clock to verify at all.
    $user = User::factory()->create();
    $tokens = $this->travel(-20)->seconds(fn () => signIn($user));
    $family = familyFor($tokens['refresh_token']);
    $issuedAt = Cache::get('lukk:unclaimed:'.$family);

    $rotated = $this->postJson('/auth/refresh', ['refresh_token' => $tokens['refresh_token']])->assertOk()->json();

    Cache::put('lukk:unclaimed:'.$family, $issuedAt, 3600);
    $this->travel(700)->seconds();

    // An access token minted by a refresh proves the session was used.
    freshRequest();
    $this->withToken($rotated['access_token'])->postJson('/auth/session/claim')->assertNoContent();

    expect(RefreshToken::where('family_id', $family)->whereNull('revoked_at')->exists())->toBeTrue()
        ->and(isUnclaimed($family))->toBeFalse();
});

it('never treats a successor minted moments after sign-in as the original', function () {
    // The rule is "is this the credential the sign-in handed out", and comparing mint times only
    // ANSWERS that in one direction: a client that refreshes a second after signing in gets a
    // successor whose own creation is inside the tolerance, so a resurrected marker revoked a session
    // in active use — exactly what the rule exists to prevent, and no configuration avoided it. The
    // family's original row is the one with no predecessor, which is exact.
    config(['lukk.claim_seconds' => 600]);
    $tokens = signIn(User::factory()->create());
    $family = familyFor($tokens['refresh_token']);
    $issuedAt = Cache::get('lukk:unclaimed:'.$family);

    $this->travel(1)->seconds();
    $rotated = $this->postJson('/auth/refresh', ['refresh_token' => $tokens['refresh_token']])->assertOk()->json();

    // The claim's delete is lost: the cache is restored from a snapshot taken before it.
    Cache::put('lukk:unclaimed:'.$family, $issuedAt, 3600);
    $this->travel(700)->seconds();

    $this->postJson('/auth/refresh', ['refresh_token' => $rotated['refresh_token']])->assertOk();

    expect(RefreshToken::where('family_id', $family)->whereNull('revoked_at')->exists())->toBeTrue()
        ->and(isUnclaimed($family))->toBeFalse();
});

it('falls back to the mint-time comparison for a repository that does not report `original`', function () {
    // `RefreshTokenRecord::$original` is newer than the documented storage seam, so unknown must mean
    // "compare the mint times" — exactly what such a repository already did, no better and no worse.
    // Defaulting it to "this is the original" instead would hand every successor to the revocation
    // path, and the repository would have gone from working to logging people out by upgrading lukk.
    config(['lukk.claim_seconds' => 600]);
    bindRepositoryReporting(original: false, createdAt: true);
    Log::spy();
    $user = User::factory()->create();

    // Refreshed 10 s in, then its marker came back: a successor, and still not revoked.
    $refreshed = signIn($user);
    $refreshedFamily = familyFor($refreshed['refresh_token']);
    $issuedAt = Cache::get('lukk:unclaimed:'.$refreshedFamily);

    $this->travel(10)->seconds();
    $rotated = $this->postJson('/auth/refresh', ['refresh_token' => $refreshed['refresh_token']])->assertOk()->json();
    Cache::put('lukk:unclaimed:'.$refreshedFamily, $issuedAt, 3600);

    // Never used at all: its original, presented late, is still revoked.
    $unclaimed = signIn($user);
    $unclaimedFamily = familyFor($unclaimed['refresh_token']);

    $this->travel(700)->seconds();

    $this->postJson('/auth/refresh', ['refresh_token' => $rotated['refresh_token']])->assertOk();
    $this->postJson('/auth/refresh', ['refresh_token' => $unclaimed['refresh_token']])->assertUnauthorized();

    expect(RefreshToken::where('family_id', $refreshedFamily)->whereNull('revoked_at')->exists())->toBeTrue()
        ->and(RefreshToken::where('family_id', $unclaimedFamily)->whereNull('revoked_at')->exists())->toBeFalse();

    // Working as documented, so nothing to warn about.
    Log::shouldNotHaveReceived('warning');
});

it('spends the whole mint-time tolerance on the original, and revokes it late all the same', function () {
    // `StartSession` writes the marker and then inserts the row, so the two timestamps are stamped
    // microseconds apart by this one server and can still land on either side of a second boundary.
    // `ORIGINAL_WITHIN_SECONDS` is the budget for exactly that, and spending all of it must still leave
    // the sign-in's own refresh token recognisable — a tolerance that stops one short of its own
    // constant turns a never-used session into one that is never revoked.
    //
    // The proximity test is the FALLBACK, so the repository has to be one that cannot answer
    // `original`; the shipped one answers it exactly and would ignore the tolerance altogether.
    config(['lukk.claim_seconds' => 600]);
    bindRepositoryReporting(original: false, createdAt: true);
    $tokens = signIn(User::factory()->create());
    $family = familyFor($tokens['refresh_token']);

    // The marker landed a full tolerance ahead of the row it belongs to.
    Cache::put('lukk:unclaimed:'.$family, Cache::get('lukk:unclaimed:'.$family) - 2, 3600);
    $this->travel(601)->seconds();

    $this->postJson('/auth/refresh', ['refresh_token' => $tokens['refresh_token']])->assertUnauthorized();

    expect(RefreshToken::where('family_id', $family)->whereNull('revoked_at')->exists())->toBeFalse();
});

it('recognises the original from `original` alone, without a createdAt and without warning', function () {
    // The inverse: `original` is the signal the rule actually wants, so a repository reporting it owes
    // nothing else. It used to be `createdAt` or nothing, which made a `$timestamps = false` model
    // silently disable the feature.
    config(['lukk.claim_seconds' => 600]);
    bindRepositoryReporting(original: true, createdAt: false);
    Log::spy();
    $tokens = signIn(User::factory()->create());
    $family = familyFor($tokens['refresh_token']);

    $this->travel(601)->seconds();

    $this->postJson('/auth/refresh', ['refresh_token' => $tokens['refresh_token']])->assertUnauthorized();

    expect(RefreshToken::where('family_id', $family)->whereNull('revoked_at')->exists())->toBeFalse();
    Log::shouldNotHaveReceived('warning');
});

it('never treats a successor as the original, however large the configured leeway', function () {
    // `leeway` is signer-to-verifier clock drift and an operator may legitimately raise it; the
    // marker and the credential's mint time both come from THIS server in one sign-in, so the
    // proximity test must not widen with it. While it did, `leeway: 120` made a successor minted 40 s
    // after sign-in pass as the original — and a resurrected marker then logged out a live session,
    // the exact outcome the "original credential only" rule exists to make impossible.
    //
    // The proximity test is the FALLBACK, so the repository has to be one that cannot answer
    // `original` — the shipped one answers it exactly, and against it this test would pass whatever
    // the tolerance were derived from, proving nothing.
    config(['lukk.claim_seconds' => 600, 'lukk.leeway' => 120]);
    bindRepositoryReporting(original: false, createdAt: true);
    $tokens = signIn(User::factory()->create());
    $family = familyFor($tokens['refresh_token']);
    $issuedAt = Cache::get('lukk:unclaimed:'.$family);

    $this->travel(40)->seconds();
    $rotated = $this->postJson('/auth/refresh', ['refresh_token' => $tokens['refresh_token']])->assertOk()->json();

    // The claim's delete is lost: the cache is restored from a snapshot taken before it.
    Cache::put('lukk:unclaimed:'.$family, $issuedAt, 3600);
    $this->travel(700)->seconds();

    $this->postJson('/auth/refresh', ['refresh_token' => $rotated['refresh_token']])->assertOk();

    expect(RefreshToken::where('family_id', $family)->whereNull('revoked_at')->exists())->toBeTrue()
        ->and(isUnclaimed($family))->toBeFalse();
});

it('clamps the window to at least access_ttl + leeway, so the original access token cannot outlive it', function () {
    // The clamp's whole guarantee: a refresh inside access_ttl + leeway is accepted, one past it is
    // revoked. A client that only refreshes after another service's 401 lands at the latter and must
    // call the claim route.
    config(['lukk.claim_seconds' => 1, 'lukk.access_ttl' => 900, 'lukk.leeway' => 5]);
    $user = User::factory()->create();

    $inside = signIn($user);
    $this->travel(905)->seconds();
    $this->postJson('/auth/refresh', ['refresh_token' => $inside['refresh_token']])->assertOk();

    $late = signIn($user);
    $this->travel(906)->seconds();
    $this->postJson('/auth/refresh', ['refresh_token' => $late['refresh_token']])->assertUnauthorized();
});

it('clamps the window to at least 60 seconds', function () {
    config(['lukk.claim_seconds' => 10, 'lukk.access_ttl' => 30, 'lukk.leeway' => 0]);
    $user = User::factory()->create();

    $inside = signIn($user);
    $this->travel(60)->seconds();
    $this->postJson('/auth/refresh', ['refresh_token' => $inside['refresh_token']])->assertOk();

    $late = signIn($user);
    $this->travel(61)->seconds();
    $this->postJson('/auth/refresh', ['refresh_token' => $late['refresh_token']])->assertUnauthorized();
});

it('rejects a late first use with 401, not a 500, on a verify-only service with no refresh_tokens table', function () {
    // A service that only verifies tokens can share the cache and the setting, but has no table to
    // revoke rows in. The denylist write is the part that matters there — the issuer revokes the rows
    // on the family's next refresh.
    config(['lukk.claim_seconds' => 600]);
    $tokens = signIn(User::factory()->create());
    $family = familyFor($tokens['refresh_token']);

    Schema::drop('refresh_tokens');
    Exceptions::fake();
    $this->travel(601)->seconds();

    freshRequest();
    $this->withToken($tokens['access_token'])->postJson('/auth/session/claim')->assertUnauthorized();

    expect(app(Denylist::class)->has('fid', $family))->toBeTrue();

    // Swallowed, not hidden. The rows were NOT revoked here, and only the report says so — on a
    // service that does own the table this is a real database failure wearing a 401.
    Exceptions::assertReported(fn (QueryException $e) => str_contains($e->getMessage(), 'refresh_tokens'));
});

it('never revokes the original refresh row once it has been rotated, even replayed inside grace with its marker back', function () {
    // Only a NEVER-ROTATED original row counts as the sign-in's credential. Rotation is a use.
    config(['lukk.claim_seconds' => 600, 'lukk.grace_seconds' => 30]);
    $tokens = signIn(User::factory()->create());
    $family = familyFor($tokens['refresh_token']);
    $issuedAt = Cache::get('lukk:unclaimed:'.$family);

    $this->travel(590)->seconds();
    $this->postJson('/auth/refresh', ['refresh_token' => $tokens['refresh_token']])->assertOk();

    Cache::put('lukk:unclaimed:'.$family, $issuedAt, 3600);
    $this->travel(20)->seconds();   // 610 s after sign-in, 20 s after rotation: a tolerated sibling

    $this->postJson('/auth/refresh', ['refresh_token' => $tokens['refresh_token']])->assertOk();

    expect(RefreshToken::where('family_id', $family)->whereNull('revoked_at')->exists())->toBeTrue();
});

it('authenticates a co-issuer token with no family as before, when the feature is on', function () {
    // Nothing to claim or revoke without a `fid`; the verify-only topology must keep working.
    config(['lukk.claim_seconds' => 600]);
    $user = User::factory()->create();
    $cfg = Lukk\Lukk::guardConfig();
    $token = JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => (string) $user->getKey(), 'jti' => 'co',
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 300,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);

    $ops = claimCacheOps();
    $this->withToken($token)->postJson('/auth/session/claim')->assertNoContent();

    expect($ops->getArrayCopy())->toBe([]);
});

it('warns once per process when a replacement repository reports neither signal, which silently disables revocation', function () {
    // With neither `original` nor `createdAt` no refresh row can be recognised as the sign-in's own, so
    // no late first use is ever revoked — the feature fails open, invisibly. Say so, once per process.
    config(['lukk.claim_seconds' => 600]);
    bindRepositoryReporting(original: false, createdAt: false);

    Log::spy();
    $user = User::factory()->create();
    $first = signIn($user);
    $second = signIn($user);

    $this->travel(601)->seconds();

    // Fails open — neither late original is revoked — and the warning is logged once, not per refresh.
    $this->postJson('/auth/refresh', ['refresh_token' => $first['refresh_token']])->assertOk();
    $this->postJson('/auth/refresh', ['refresh_token' => $second['refresh_token']])->assertOk();

    // The whole sentence, not a few substrings in it: the warning IS the feature here — it is the only
    // thing that tells an operator which of their own classes to change, and half a sentence, or one
    // assembled in the wrong order, says nothing actionable while still mentioning every keyword.
    $expected = 'lukk: claim_seconds is on for guard [api], but its refresh token '
        .'records report neither original nor createdAt, so an unclaimed session\'s original '
        .'refresh token can never be recognised and is never revoked. A replacement '
        .'RefreshTokenRepository must populate RefreshTokenRecord::$original, or failing that '
        .'$createdAt.';

    Log::shouldHaveReceived('warning')
        ->once()
        ->withArgs(fn (string $message) => $message === $expected
            // Kept explicit: a future rewording is copied into `$expected`, and this is what stops one
            // that interpolates the session it was noticed on from being copied in with it.
            && ! str_contains($message, $first['refresh_token'])
            && ! str_contains($message, familyFor($first['refresh_token'])));
});

it('never fails a refresh because logging the unrecognisable-original warning throws', function () {
    // The warning is a diagnostic riding on an authentication request. A broken log channel must not
    // turn it into a 500, on the first refresh or any later one.
    config(['lukk.claim_seconds' => 600]);
    bindRepositoryReporting(original: false, createdAt: false);

    Log::spy();
    Log::shouldReceive('warning')->once()->andThrow(new RuntimeException('log channel down'));

    $user = User::factory()->create();
    $first = signIn($user);
    $second = signIn($user);

    $this->travel(601)->seconds();

    $this->postJson('/auth/refresh', ['refresh_token' => $first['refresh_token']])->assertOk();
    $this->postJson('/auth/refresh', ['refresh_token' => $second['refresh_token']])->assertOk();
});
