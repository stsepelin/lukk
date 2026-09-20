<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiter;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\ChallengeTwoFactor;
use Lukk\Actions\VerifyTwoFactorChallenge;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Lockout\DatabaseLockoutRepository;
use Lukk\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

uses()->group('two-factor');

beforeEach(fn () => $this->freezeSecond());

/** A confirmed-2FA user and its plaintext secret; one recovery code, `RECOVERY-1`. */
function v2faUser(): array
{
    $user = User::factory()->create();
    $secret = app(TwoFactorProvider::class)->generateSecret();

    $user->forceFill([
        'two_factor_secret' => Crypt::encryptString($secret),
        'two_factor_recovery_codes' => json_encode([Hash::make('RECOVERY-1')]),
        'two_factor_confirmed_at' => now(),
    ])->save();

    return [$user, $secret];
}

function v2faChallenge(User $user): string
{
    return app(ChallengeToken::class)->issue('2fa', $user->getKey(), 300);
}

function v2faAction(int $max = 5, int $decay = 60, ?DatabaseLockoutRepository $lockouts = null, ?string $guard = 'api'): VerifyTwoFactorChallenge
{
    return new VerifyTwoFactorChallenge(
        app(ChallengeToken::class), app(ChallengeTwoFactor::class), app(RateLimiter::class),
        $max, $decay, $lockouts, $guard,
    );
}

/** Run the action and return the ValidationException it threw. */
function v2faRefusal(Closure $call): ValidationException
{
    try {
        $call();
    } catch (ValidationException $e) {
        return $e;
    }

    throw new RuntimeException('Expected the challenge to be refused.');
}

function v2faLock(DatabaseLockoutRepository $lockouts, User $user, string $guard = 'api'): void
{
    for ($i = 0; $i < $lockouts->maxAttempts(); $i++) {
        $lockouts->recordFailure('two_factor', (string) $user->getKey(), $guard);
    }
}

function v2faAttempts(User $user, string $guard = 'api'): int
{
    return (int) DB::table('lukk_lockouts')
        ->where(['purpose' => 'two_factor', 'subject' => (string) $user->getKey(), 'guard' => $guard])
        ->value('attempts');
}

it('names the challenge field when the challenge does not verify', function () {
    $e = v2faRefusal(fn () => v2faAction()('not-a-challenge', '123456', null));

    expect($e->errors())->toBe(['challenge_token' => ['The two-factor challenge is invalid or has expired.']]);
});

it('spends the challenge on success, whichever credential redeems it next', function () {
    // The TOTP replay cache would refuse a second use of the same CODE on its own, so a test that
    // replays the code proves nothing about the challenge. A different, valid credential does.
    [$user, $secret] = v2faUser();
    $challenge = v2faChallenge($user);

    expect(v2faAction()($challenge, app(Google2FA::class)->getCurrentOtp($secret), null)->getKey())->toBe($user->getKey());

    $e = v2faRefusal(fn () => v2faAction()($challenge, null, 'RECOVERY-1'));

    expect($e->errors())->toHaveKey('challenge_token');
});

it('counts a wrong code against the account and refuses once the budget is spent', function () {
    // The route's per-IP throttle trips first over HTTP, so only a direct call reaches this bucket.
    [$user] = v2faUser();
    $challenge = v2faChallenge($user);

    v2faRefusal(fn () => v2faAction(max: 1)($challenge, '000000', null));

    expect(app(RateLimiter::class)->attempts('lukk:2fa-challenge:api:'.$user->getKey()))->toBe(1)
        ->and(v2faRefusal(fn () => v2faAction(max: 1)($challenge, '000000', null))->status)->toBe(429);
});

it('returns the account budget on success', function () {
    [$user, $secret] = v2faUser();
    $key = 'lukk:2fa-challenge:api:'.$user->getKey();

    v2faRefusal(fn () => v2faAction()(v2faChallenge($user), '000000', null));
    expect(app(RateLimiter::class)->attempts($key))->toBe(1);

    v2faAction()(v2faChallenge($user), app(Google2FA::class)->getCurrentOtp($secret), null);

    expect(app(RateLimiter::class)->attempts($key))->toBe(0);
});

it('keys the account budget by guard', function () {
    [$user] = v2faUser();
    $challenge = v2faChallenge($user);
    app(RateLimiter::class)->hit('lukk:2fa-challenge:admin:'.$user->getKey());

    // Spent on `admin` — and only there.
    expect(v2faRefusal(fn () => v2faAction(max: 1, guard: 'admin')($challenge, '000000', null))->status)->toBe(429)
        ->and(v2faRefusal(fn () => v2faAction(max: 1, guard: 'api')($challenge, '000000', null))->status)->toBe(422);
});

it('falls back to the default guard for the account budget', function () {
    [$user] = v2faUser();
    app(RateLimiter::class)->hit('lukk:2fa-challenge:api:'.$user->getKey());

    expect(v2faRefusal(fn () => v2faAction(max: 1, guard: null)(v2faChallenge($user), '000000', null))->status)->toBe(429);
});

it('states the wait in the throttle message, rounded UP to whole minutes', function (int $decay, string $expected) {
    // 60 s is exactly one minute and 61 s is two: the boundary both ways, so the divisor, the
    // rounding direction and the rounding mode are each pinned by one of the two.
    app('translator')->addLines(['auth.throttle' => 'Wait :seconds s (:minutes min).'], 'en');
    [$user] = v2faUser();
    $challenge = v2faChallenge($user);

    v2faRefusal(fn () => v2faAction(max: 1, decay: $decay)($challenge, '000000', null));
    $e = v2faRefusal(fn () => v2faAction(max: 1, decay: $decay)($challenge, '000000', null));

    expect($e->status)->toBe(429)
        ->and($e->errors())->toBe(['code' => [$expected]]);
})->with([
    'exactly a minute' => [60, 'Wait 60 s (1 min).'],
    'one second over' => [61, 'Wait 61 s (2 min).'],
]);

it('answers a locked account with 423 before the rate limit, and counts nothing more', function () {
    // A locked account owes 423 whatever its limiter says, and a request refused by the lock must
    // not advance the run it is refused for.
    [$user, $secret] = v2faUser();
    $lockouts = new DatabaseLockoutRepository(3, 0);
    v2faLock($lockouts, $user);
    app(RateLimiter::class)->hit('lukk:2fa-challenge:api:'.$user->getKey());

    $e = v2faRefusal(fn () => v2faAction(max: 1, lockouts: $lockouts)(v2faChallenge($user), app(Google2FA::class)->getCurrentOtp($secret), null));

    expect($e->status)->toBe(423)
        ->and(v2faAttempts($user))->toBe(3);
});

it('names the auto-release wait of the guard it runs under', function () {
    app('translator')->addLines(['auth.throttle' => 'Wait :seconds s.'], 'en');
    [$user, $secret] = v2faUser();
    $lockouts = new DatabaseLockoutRepository(3, 600);
    v2faLock($lockouts, $user, 'admin');

    $e = v2faRefusal(fn () => v2faAction(lockouts: $lockouts, guard: 'admin')(v2faChallenge($user), '000000', null));

    expect($e->status)->toBe(423)
        ->and($e->errors())->toBe(['code' => ['Wait 600 s.']]);
});

it('exempts only a recovery-code-ONLY attempt from the lock', function (?string $code, ?string $recovery, bool $passes) {
    // An empty string is "not given" — the action is reachable directly, not only through the
    // request that turns '' into null.
    [$user] = v2faUser();
    $lockouts = new DatabaseLockoutRepository(3, 0);
    v2faLock($lockouts, $user);

    $call = fn () => v2faAction(lockouts: $lockouts)(v2faChallenge($user), $code, $recovery);

    if ($passes) {
        expect($call()->getKey())->toBe($user->getKey());
    } else {
        expect(v2faRefusal($call)->status)->toBe(423);
    }
})->with([
    'recovery code, null code' => [null, 'RECOVERY-1', true],
    'recovery code, empty code' => ['', 'RECOVERY-1', true],
    'code and recovery code' => ['000000', 'RECOVERY-1', false],
    'empty recovery code' => [null, '', false],
    'neither' => [null, null, false],
]);

it('returns the reserved slot on success, so correct codes never add up to a lock', function () {
    // Each TOTP attempt reserves a failure before the code is checked. Without the release, every
    // successful sign-in left one behind and the cap-th one locked the account.
    [$user, $secret] = v2faUser();
    $lockouts = new DatabaseLockoutRepository(3, 0);

    v2faAction(lockouts: $lockouts)(v2faChallenge($user), app(Google2FA::class)->getCurrentOtp($secret), null);

    expect(DB::table('lukk_lockouts')->where('purpose', 'two_factor')->exists())->toBeFalse();
});

it('states a lock\'s auto-release wait rounded UP to whole minutes', function (int $releaseAfter, string $expected) {
    // 60 s is one minute and 61 s two: the boundary both ways, as for the throttle message.
    app('translator')->addLines(['auth.throttle' => 'Wait :seconds s (:minutes min).'], 'en');
    [$user] = v2faUser();
    $lockouts = new DatabaseLockoutRepository(3, $releaseAfter);
    v2faLock($lockouts, $user);

    $e = v2faRefusal(fn () => v2faAction(lockouts: $lockouts)(v2faChallenge($user), '000000', null));

    expect($e->status)->toBe(423)
        ->and($e->errors())->toBe(['code' => [$expected]]);
})->with([
    'exactly a minute' => [60, 'Wait 60 s (1 min).'],
    'one second over' => [61, 'Wait 61 s (2 min).'],
]);
