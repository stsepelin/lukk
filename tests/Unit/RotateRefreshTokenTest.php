<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Lukk\Actions\RevokeSession;
use Lukk\Actions\RotateRefreshToken;
use Lukk\Contracts\Denylist;
use Lukk\Events\RefreshFamilyForked;
use Lukk\Events\RefreshTokenReused;
use Lukk\Exceptions\InvalidRefreshToken;
use Lukk\Lukk;
use Lukk\Models\RefreshToken;
use Lukk\Refresh\DatabaseRefreshTokenRepository;
use Lukk\Support\RefreshTokenRecord;
use Lukk\Tests\Fixtures\User;

uses()->group('refresh');

// Freeze the clock so timestamps come from one instant. The grace check compares
// integer-second timestamps (`rotated_at + grace < now`); without freezing, the
// gap between a real `rotate()` and a later `travel()` can straddle a wall-clock
// second and shift the effective delta by 1s, flaking the exact-boundary cases.
beforeEach(fn () => $this->freezeSecond());

function familyId(): string
{
    return RefreshToken::query()->value('family_id');
}

it('issues a usable pair at login and stores only the hash', function () {
    $pair = start()(1);

    expect($pair->accessToken)->toBeString()->and($pair->expiresIn)->toBe(900);
    expect(RefreshToken::count())->toBe(1);
    expect(RefreshToken::where('token_hash', hash('sha256', $pair->refreshToken))->exists())->toBeTrue();
    expect(RefreshToken::where('token_hash', $pair->refreshToken)->exists())->toBeFalse();
});

it('rotates: stamps the parent and chains a successor in the same family', function () {
    $pair = start()(7);
    $out = rotate()($pair->refreshToken);

    expect($out->refreshToken)->not->toBe($pair->refreshToken);
    $rows = RefreshToken::orderBy('created_at')->get();
    expect($rows)->toHaveCount(2);
    expect($rows[0]->rotated_at)->not->toBeNull();
    expect($rows[1]->previous_id)->toBe($rows[0]->id);
    expect($rows[1]->family_id)->toBe($rows[0]->family_id);
});

it('rejects an unknown refresh token', function () {
    expect(fn () => rotate()('nope'))->toThrow(InvalidRefreshToken::class);
});

it('rejects an unknown refresh token without any side effects', function () {
    start()(1);
    $before = RefreshToken::count();

    expect(fn () => rotate()('never-issued'))->toThrow(InvalidRefreshToken::class);

    expect(RefreshToken::count())->toBe($before);
    expect(RefreshToken::whereNotNull('revoked_at')->count())->toBe(0);
});

it('rejects an expired refresh token', function () {
    config(['lukk.refresh_ttl' => 1]);
    $pair = start()(1);
    $this->travel(5)->seconds();
    expect(fn () => rotate()($pair->refreshToken))->toThrow(InvalidRefreshToken::class);
});

it('tolerates concurrent reuse within the grace window without logging out', function () {
    $pair = start()(1);
    $first = rotate()($pair->refreshToken);
    $second = rotate()($pair->refreshToken);

    expect($second->refreshToken)->not->toBe($first->refreshToken);
    expect(RefreshToken::where('family_id', familyId())->whereNotNull('revoked_at')->count())->toBe(0);
    expect(RefreshToken::where('family_id', familyId())->count())->toBe(3);
});

it('tolerates a replay at exactly the grace boundary (pins < not <=)', function () {
    config(['lukk.grace_seconds' => 30]);
    $pair = start()(1);
    rotate()($pair->refreshToken);

    $this->travel(30)->seconds();

    $sibling = rotate()($pair->refreshToken);

    expect($sibling->refreshToken)->toBeString();
    expect(RefreshToken::where('family_id', familyId())->whereNotNull('revoked_at')->count())->toBe(0);
});

it('revokes the whole family when a consumed token is replayed after grace', function () {
    $pair = start()(1);
    rotate()($pair->refreshToken);
    $this->travel(31)->seconds();

    try {
        rotate()($pair->refreshToken);
        $this->fail('expected InvalidRefreshToken');
    } catch (InvalidRefreshToken $e) {
        expect($e->reason)->toBe('reuse');
    }

    expect(RefreshToken::where('family_id', familyId())->whereNull('revoked_at')->count())->toBe(0);
});

it('dispatches a security event when a reused token triggers a family revoke', function () {
    Event::fake([RefreshTokenReused::class]);

    $pair = start()(1);
    rotate()($pair->refreshToken);
    $this->travel(31)->seconds();
    $fid = familyId();

    expect(fn () => rotate()($pair->refreshToken))->toThrow(InvalidRefreshToken::class);

    Event::assertDispatched(
        RefreshTokenReused::class,
        fn (RefreshTokenReused $e) => $e->familyId === $fid && $e->reason === 'reuse',
    );
});

it('kills the family if a hard-revoked token is presented', function () {
    $pair = start()(1);
    revokeSession()(familyId());

    try {
        rotate()($pair->refreshToken);
        $this->fail('expected InvalidRefreshToken');
    } catch (InvalidRefreshToken $e) {
        expect($e->reason)->toBe('revoked');
    }
});

it('revoke-all revokes only that user', function () {
    start()(42);
    start()(42);
    start()(99);
    revokeAll()(42);

    expect(RefreshToken::where('user_id', 42)->whereNull('revoked_at')->count())->toBe(0);
    expect(RefreshToken::where('user_id', 99)->whereNull('revoked_at')->count())->toBe(1);
});

it('denylists the family so its access tokens stop verifying immediately', function () {
    $pair = start()(99);
    expect(verifier()->verify($pair->accessToken))->not->toBeNull();

    revokeSession()(familyId());
    expect(verifier()->verify($pair->accessToken))->toBeNull();
});

it('does not issue a successor into a family whose revoke is already in flight', function () {
    // `revokeFamily` is a set-based UPDATE; under READ COMMITTED (PostgreSQL) its snapshot can miss
    // a successor inserted by an in-flight rotation, leaving a live row the holder keeps rotating —
    // so a logout-all or a reuse kill undoes itself once the denylist entry expires. Both revoke
    // paths write the denylist BEFORE the rows, so seeing it means a revoke is under way.
    $pair = User::factory()->create()->startSession();

    // Exactly the intermediate state: denylisted, rows not yet updated.
    app(Denylist::class)->revokeFamily(familyId(), 900);

    expect(fn () => rotate()($pair->refreshToken))->toThrow(InvalidRefreshToken::class);

    // And nothing live survives in the family to rotate with later.
    expect(RefreshToken::query()->whereNull('revoked_at')->count())->toBe(0);
});

it('reports a family carrying more live tokens than concurrency explains', function () {
    // The grace window mints a sibling rather than revoking, which is what stops a multi-tab client
    // logging itself out — and is also what a thief racing inside the window gets. Both chains then
    // rotate forever without colliding, so nothing else in lukk can see the fork.
    Event::fake([RefreshFamilyForked::class]);
    config(['lukk.grace_seconds' => 60]);
    $pair = User::factory()->create()->startSession();

    // Re-consume the same parent repeatedly, inside grace — each pass mints another sibling.
    foreach (range(1, 4) as $i) {
        rotate()($pair->refreshToken);
    }

    Event::assertDispatched(RefreshFamilyForked::class, fn ($e) => $e->liveTokens > 3);
});

it('does not let a throwing fork listener cost the client its whole family', function () {
    // The event is ADVISORY. Dispatched between the commit and the return, a listener that threw — an
    // alerting hook answering 500 is the realistic one — left the successor committed while the caller
    // got an exception. Past the grace window that is indistinguishable from a replay, so the retry
    // tripped reuse detection and revoked everything. That is exactly the hole the mint was moved
    // inside the transaction to close.
    config(['lukk.grace_seconds' => 60]);
    Event::listen(RefreshFamilyForked::class, function () {
        throw new RuntimeException('consumer listener blew up');
    });

    $pair = User::factory()->create()->startSession();
    // Exactly the shape of the test above: re-consume the same parent inside grace, four times, which
    // takes the family past the default `fork_threshold` and fires the event on the last pass.
    $forked = null;
    foreach (range(1, 4) as $i) {
        $forked = rotate()($pair->refreshToken);
    }

    // The caller got its successor rather than the listener's exception.
    expect($forked->refreshToken)->not->toBe('');

    // And the family is intact: that successor still rotates past the grace window, with no reuse
    // revoke — the outcome a lost successor produced.
    test()->travel(61)->seconds();
    expect(fn () => rotate()($forked->refreshToken))->not->toThrow(Throwable::class);
});

it('stays quiet for the two or three siblings ordinary concurrency produces', function () {
    Event::fake([RefreshFamilyForked::class]);
    config(['lukk.grace_seconds' => 60]);
    $pair = User::factory()->create()->startSession();

    rotate()($pair->refreshToken);
    rotate()($pair->refreshToken);

    Event::assertNotDispatched(RefreshFamilyForked::class);
});

it('honours a grace window that reaches the Action as a string', function () {
    // `config/lukk.php` reads `LUKK_GRACE` through `env()`, which answers with a string, and no lukk
    // key is guaranteed to have been through that file at all (`mergeConfigDeep` early-returns on a
    // cached config). `$grace` is handed straight to two `int`-typed helpers under `strict_types`, so
    // without the cast the FIRST refresh of every session is a TypeError instead of a rotation. And
    // it has to be honoured as a number, not as a string: the boundary is 3 seconds either way.
    config(['lukk.grace_seconds' => '3']);
    $pair = start()(1);
    rotate()($pair->refreshToken);

    $this->travel(3)->seconds();
    expect(rotate()($pair->refreshToken)->refreshToken)->toBeString();

    $this->travel(1)->seconds();
    expect(fn () => rotate()($pair->refreshToken))->toThrow(InvalidRefreshToken::class);
});

it('falls back to a 30-second grace window when the key is missing, measured from the first use', function () {
    // An install that ran `config:cache` before a key existed reaches the Action without it, so the
    // in-code default is what decides whether a multi-tab client keeps its session. Pinned at both
    // edges — and from the FIRST consumption: `rotated_at` is stamped once and a sibling mint leaves
    // it alone, so the window cannot slide forward one replay at a time.
    config(['lukk.grace_seconds' => null]);
    $pair = start()(1);
    rotate()($pair->refreshToken);

    $this->travel(30)->seconds();
    expect(rotate()($pair->refreshToken)->refreshToken)->toBeString();
    expect(RefreshToken::where('family_id', familyId())->whereNotNull('revoked_at')->count())->toBe(0);

    // One second later: 31 s after the first consumption, and only 1 s after the sibling.
    $this->travel(1)->seconds();
    expect(fn () => rotate()($pair->refreshToken))->toThrow(InvalidRefreshToken::class);
});

it('still rotates a token whose expiry is exactly now, with the application claims intact', function () {
    // Two `<` comparisons see this token and both must stay strict. The locked read's expiry check
    // decides whether the client is logged out a second early; `rejectable()` decides whether
    // `tokenClaimsUsing` is consulted at all, so `<=` there mints a successor that silently lost the
    // application's claims — an outage that only shows up downstream, in whatever reads them.
    Lukk::tokenClaimsUsing(fn () => ['tier' => 'gold']);
    config(['lukk.refresh_ttl' => 3]);
    $pair = start()(1);

    // Exactly `expires_at`: 3 s of a 3 s lifetime. Kept inside the 5 s verification leeway, because
    // firebase/php-jwt validates the successor's `nbf` against real `time()`, not the frozen clock.
    $this->travel(3)->seconds();

    expect(claims(rotate()($pair->refreshToken)->accessToken)->tier)->toBe('gold');
});

it('resolves the abilities of a token whose expiry is exactly now', function () {
    // The same boundary, one comparison further in. `abilitiesFor()` returning null for a token the
    // transaction is about to accept does not fail loudly: the issuer reads null as "abilities are
    // not in use" and mints a token with no `scope` at all, which every gated route then 403s.
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    config(['lukk.refresh_ttl' => 3]);
    $pair = start()(1);
    $this->travel(3)->seconds();

    expect(claims(rotate()($pair->refreshToken)->accessToken)->scope)->toBe('orders.read');
});

it('gives a sibling minted at the exact grace boundary the application claims', function () {
    // The grace branch is the multi-tab client's normal path, so everything the successor of a FRESH
    // token gets, the sibling gets too. `rejectable()` is what stands between this token and
    // `tokenClaimsUsing`, and at exactly `rotated_at + grace` it must still answer "not rejectable" —
    // both an off-by-one (`<=`) and a sign flip (`-`) make it drop the claims silently.
    config(['lukk.grace_seconds' => 3]);
    Lukk::tokenClaimsUsing(fn () => ['tier' => 'gold']);
    $pair = start()(1);
    rotate()($pair->refreshToken);

    $this->travel(3)->seconds();

    expect(claims(rotate()($pair->refreshToken)->accessToken)->tier)->toBe('gold');
});

it('gives a sibling minted at the exact grace boundary the same abilities', function () {
    // And the same boundary in `abilitiesFor()`, where the failure is worse than a missing claim: a
    // null grant is "abilities not in use", so the sibling comes back with no `scope` and the tab
    // that minted it is locked out of every gated route until it logs in again.
    config(['lukk.grace_seconds' => 3]);
    Lukk::abilitiesUsing(fn () => ['orders.read']);
    $pair = start()(1);
    rotate()($pair->refreshToken);

    $this->travel(3)->seconds();

    expect(claims(rotate()($pair->refreshToken)->accessToken)->scope)->toBe('orders.read');
});

it('never asks the application about a token it has already refused', function () {
    // Consumer callbacks are resolved before the transaction opens, which also puts them ahead of
    // every reject branch — so they are gated on `rejectable()` instead. A revoked token is not
    // expired and not rotated, so only the first of its three clauses catches it: fold that `||` into
    // an `&&` and lukk queries the application's permission store on behalf of a dead session, which
    // is both a pointless round trip on an attacker-triggerable path and a callback that can throw
    // where a throw pre-empts the refusal.
    $pair = start()(1);
    revokeSession()(familyId());

    // Registered only now: login legitimately consults the hook, and counting that call would say
    // nothing about the refresh.
    $calls = 0;
    Lukk::tokenClaimsUsing(function () use (&$calls) {
        $calls++;

        return [];
    });

    expect(fn () => rotate()($pair->refreshToken))->toThrow(InvalidRefreshToken::class);
    expect($calls)->toBe(0);
});

it('reports the fork once, and only past the default threshold of three', function () {
    // The default matters on its own: `fork_threshold` is not guaranteed to be in the config either,
    // and the signal is only useful if it is quiet at what ordinary concurrency produces. Three live
    // siblings is a browser opening tabs; four is the fan-out worth looking at. Exactly once, and
    // carrying the number of live tokens the family actually holds — an off-by-one here reports a
    // fork that has not happened yet, which is the same alert fatigue as no threshold at all.
    Event::fake([RefreshFamilyForked::class]);
    config(['lukk.grace_seconds' => 60, 'lukk.fork_threshold' => null]);
    $pair = User::factory()->create()->startSession();

    foreach (range(1, 3) as $i) {
        rotate()($pair->refreshToken);
    }

    Event::assertNotDispatched(RefreshFamilyForked::class);

    rotate()($pair->refreshToken);

    expect(RefreshToken::where('family_id', familyId())->whereNull('rotated_at')->whereNull('revoked_at')->count())->toBe(4);
    Event::assertDispatchedTimes(RefreshFamilyForked::class, 1);
    Event::assertDispatched(RefreshFamilyForked::class, fn (RefreshFamilyForked $e) => $e->liveTokens === 4);
});

it('honours a configured fork threshold, including one that arrives as a string', function () {
    // `LUKK_FORK_THRESHOLD` comes from `env()` like every other tunable, so the configured value can
    // be a string — and `forkThreshold()` is typed `int`, so without the cast a deployment that sets
    // it cannot refresh at all. Above the threshold it must still fire, or raising it turns the
    // signal off rather than turning it down.
    Event::fake([RefreshFamilyForked::class]);
    config(['lukk.grace_seconds' => 60, 'lukk.fork_threshold' => '5']);
    $pair = User::factory()->create()->startSession();

    foreach (range(1, 5) as $i) {
        rotate()($pair->refreshToken);
    }

    Event::assertNotDispatched(RefreshFamilyForked::class);

    rotate()($pair->refreshToken);

    Event::assertDispatchedTimes(RefreshFamilyForked::class, 1);
    Event::assertDispatched(RefreshFamilyForked::class, fn (RefreshFamilyForked $e) => $e->liveTokens === 6);
});

it('keeps the floor of two when the threshold is configured below it', function () {
    // Two siblings is what a browser opening a second tab, or an SSR render racing the client,
    // produces on its own. A configured 1 would report every one of them, so the floor holds — and it
    // is a floor, not a replacement: the third sibling still fires.
    Event::fake([RefreshFamilyForked::class]);
    config(['lukk.grace_seconds' => 60, 'lukk.fork_threshold' => 1]);
    $pair = User::factory()->create()->startSession();

    rotate()($pair->refreshToken);
    rotate()($pair->refreshToken);

    Event::assertNotDispatched(RefreshFamilyForked::class);

    rotate()($pair->refreshToken);

    Event::assertDispatchedTimes(RefreshFamilyForked::class, 1);
    Event::assertDispatched(RefreshFamilyForked::class, fn (RefreshFamilyForked $e) => $e->liveTokens === 3);
});

it('reports a throwing fork listener rather than swallowing it', function () {
    // The rotation stands when an advisory listener blows up — but silently is the wrong kind of
    // stands. The listener is usually the alerting hook itself, so if its failure is not reported the
    // fork signal is off and nothing anywhere says so.
    Exceptions::fake();
    config(['lukk.grace_seconds' => 60]);
    Event::listen(RefreshFamilyForked::class, function () {
        throw new RuntimeException('consumer listener blew up');
    });

    $pair = User::factory()->create()->startSession();
    foreach (range(1, 4) as $i) {
        rotate()($pair->refreshToken);
    }

    Exceptions::assertReported(RuntimeException::class);
});

it('says what to do when the pre-read disagrees with the locked read', function () {
    // The refusal is fail-closed and, by construction, something an operator will only ever see as an
    // unexplained 500 in the middle of a refresh. The message has to carry both halves: WHICH two
    // reads disagreed, and that nothing was consumed — because the instinctive response to a failed
    // refresh is to revoke the family, and here that would log out a session that is perfectly fine
    // and whose very next request succeeds.
    $pair = User::factory()->create()->startSession();

    $blind = new class extends DatabaseRefreshTokenRepository
    {
        public function findByHash(string $hash): ?RefreshTokenRecord
        {
            return null;   // a replica that has not caught up
        }
    };

    $rotate = new RotateRefreshToken(
        $blind,
        issuer(),
        app(RevokeSession::class),
        app(Denylist::class),
        Lukk::guardConfig(),
        Lukk::currentGuard(),
    );

    expect(fn () => $rotate($pair->refreshToken))->toThrow(
        RuntimeException::class,
        'the pre-transaction read disagreed with the locked read. Nothing was consumed; retry.',
    );
});
