<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Lukk\Events\PasswordChanged;
use Lukk\Models\Lockout;
use Lukk\Tests\Fixtures\User;

uses()->group('change-password');

/** A signed-in user plus the pair for the session they're doing it from. */
function signedIn(string $password = 'password'): array
{
    $user = User::factory()->create(['password' => bcrypt($password)]);

    return [$user, $user->startSession()];
}

it('changes the password once the current one is proven', function () {
    [$user, $pair] = signedIn();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password',
        'password' => 'new-password-1',
        'password_confirmation' => 'new-password-1',
    ])->assertOk()->assertJson(['status' => 'password-changed']);

    expect(Hash::check('new-password-1', $user->fresh()->password))->toBeTrue();

    // And the new password is one the LOGIN route will actually accept — the bound length exists
    // so a change can't lock someone out of the account they just secured.
    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'new-password-1'])->assertOk();
});

it('refuses a wrong current password, and changes nothing', function () {
    // The point of asking: a stolen access token alone must not be enough to take the account
    // over permanently, which is exactly what changing the password would do.
    [$user, $pair] = signedIn();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'not-the-password',
        'password' => 'new-password-1',
        'password_confirmation' => 'new-password-1',
    ])->assertStatus(422)->assertJsonValidationErrors(['current_password']);

    expect(Hash::check('password', $user->fresh()->password))->toBeTrue();
});

it('requires authentication', function () {
    $this->postJson('/auth/password', [
        'current_password' => 'password',
        'password' => 'new-password-1',
        'password_confirmation' => 'new-password-1',
    ])->assertStatus(401);
});

it('revokes every other session but keeps the one it was done from', function () {
    // Changing a password is what someone does when they think another party is in the account, so
    // leaving those sessions alive would defeat the point — but logging the user out of the tab
    // they just did it in is a bad answer to a good instinct.
    [$user, $current] = signedIn();
    app('auth')->forgetGuards();
    $other = $user->startSession();

    app('auth')->forgetGuards();
    $this->withToken($current->accessToken)->postJson('/auth/password', [
        'current_password' => 'password',
        'password' => 'new-password-1',
        'password_confirmation' => 'new-password-1',
    ])->assertOk();

    // The other session's refresh token is dead...
    app('auth')->forgetGuards();
    $this->postJson('/auth/refresh', ['refresh_token' => $other->refreshToken])->assertStatus(401);

    // ...and this one still rotates.
    app('auth')->forgetGuards();
    $this->postJson('/auth/refresh', ['refresh_token' => $current->refreshToken])->assertOk();
});

it('fires PasswordChanged with the user', function () {
    Event::fake([PasswordChanged::class]);
    [$user, $pair] = signedIn();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password',
        'password' => 'new-password-1',
        'password_confirmation' => 'new-password-1',
    ])->assertOk();

    Event::assertDispatched(PasswordChanged::class, fn ($e) => $e->user->is($user));
});

it('rejects a new password that fails confirmation, or repeats the current one', function () {
    [$user, $pair] = signedIn();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password',
        'password' => 'new-password-1',
        'password_confirmation' => 'mismatched',
    ])->assertStatus(422)->assertJsonValidationErrors(['password']);

    // A no-op would report success for a change that didn't happen — and this endpoint revokes
    // every other session, which is a lot of collateral for nothing.
    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password',
        'password' => 'password',
        'password_confirmation' => 'password',
    ])->assertStatus(422)->assertJsonValidationErrors(['password']);

    expect(Hash::check('password', $user->fresh()->password))->toBeTrue();
});

it('shares the step-up throttle, so it is not a second budget for the same secret', function () {
    // Two independent allowances for guessing one password is just a larger allowance.
    config(['lukk.rate_limits.confirm.max_attempts' => 3]);
    [, $pair] = signedIn();

    $wrong = fn () => test()->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'wrong', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ]);

    app('auth')->forgetGuards();
    $wrong()->assertStatus(422);
    app('auth')->forgetGuards();
    $wrong()->assertStatus(422);

    // The third attempt is spent on the CONFIRM endpoint — same budget, so this one is out.
    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->postJson('/auth/confirm-password', ['password' => 'wrong'])->assertStatus(422);

    app('auth')->forgetGuards();
    $wrong()->assertStatus(429);
});

it('counts a wrong current password toward the confirm lockout', function () {
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 3, 'lukk.rate_limits.confirm.max_attempts' => 500]);
    [$user, $pair] = signedIn();

    foreach (range(1, 3) as $i) {
        app('auth')->forgetGuards();
        $this->withToken($pair->accessToken)->postJson('/auth/password', [
            'current_password' => 'wrong', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
        ])->assertStatus(422);
    }

    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertStatus(423);

    expect(Lockout::where('purpose', 'confirm')->where('subject', (string) $user->getKey())->exists())->toBeTrue();
});

it('clears the confirm lock on success, since those failures were against the old password', function () {
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 500, 'lukk.rate_limits.confirm.max_attempts' => 500]);
    [, $pair] = signedIn();

    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'wrong', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertStatus(422);

    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertOk();

    expect(Lockout::where('purpose', 'confirm')->exists())->toBeFalse();
});

it('does not leave the caller stranded when the token carries no family', function () {
    // No family id means no "current" session to preserve, so nothing is revoked rather than
    // everything — silently logging someone out of the session they're using is the worse answer.
    [$user, $pair] = signedIn();
    $other = $user->startSession();

    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->withoutMiddleware()->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ]);

    expect(DB::table('refresh_tokens')->count())->toBeGreaterThan(0);
});

it('refuses a change that lost the reservation race', function () {
    // The state a concurrent overrun leaves: several requests passed the "not locked" gate together
    // and incremented past the cap before any of them locked the row. Seeded directly, because it
    // is by definition not reachable one request at a time.
    config(['lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 3, 'lukk.rate_limits.confirm.max_attempts' => 500]);
    [$user, $pair] = signedIn();
    Lockout::create([
        'purpose' => 'confirm', 'subject' => (string) $user->getKey(), 'guard' => 'api',
        'attempts' => 3, 'locked_at' => null,
    ]);

    // `locked_at` is null so the gate lets it through — the reservation is what stops it. Even the
    // CORRECT current password is refused, which is what "no verification happened" looks like.
    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertStatus(423);

    expect(Hash::check('password', $user->fresh()->password))->toBeTrue();
});
