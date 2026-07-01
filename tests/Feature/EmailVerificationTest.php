<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Verified;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use Lukk\Tests\Fixtures\User;

uses()->group('email-verification');

/** A valid signed verify link for the user, as lukk's notification would build it. */
function verifyUrl(User $user): string
{
    return URL::temporarySignedRoute('lukk.verification.verify', now()->addMinutes(60), [
        'id' => $user->getKey(),
        'hash' => sha1($user->getEmailForVerification()),
    ]);
}

it('verifies an email from a valid signed link and fires Verified', function () {
    Event::fake([Verified::class]);
    $user = User::factory()->create(['email_verified_at' => null]);

    // No frontend_url configured → 204 (rather than a redirect).
    $this->get(verifyUrl($user))->assertNoContent();

    expect($user->fresh()->hasVerifiedEmail())->toBeTrue();
    Event::assertDispatched(Verified::class);
});

it('redirects a browser click to the configured frontend URL with ?verified=1', function () {
    config(['lukk.email_verification.frontend_url' => 'https://app.test/verify']);
    $user = User::factory()->create(['email_verified_at' => null]);

    $this->get(verifyUrl($user), ['Accept' => 'text/html'])
        ->assertRedirect('https://app.test/verify?verified=1');

    expect($user->fresh()->hasVerifiedEmail())->toBeTrue();
});

it('returns 204 for a JSON client even when a frontend URL is set', function () {
    config(['lukk.email_verification.frontend_url' => 'https://app.test/verify']);
    $user = User::factory()->create(['email_verified_at' => null]);

    $this->getJson(verifyUrl($user))->assertNoContent();

    expect($user->fresh()->hasVerifiedEmail())->toBeTrue();
});

it('rejects a tampered verification link (403)', function () {
    $user = User::factory()->create(['email_verified_at' => null]);

    $this->getJson(verifyUrl($user).'&tampered=1')->assertStatus(403);

    expect($user->fresh()->hasVerifiedEmail())->toBeFalse();
});

it('rejects a link whose hash does not match the email (403)', function () {
    $user = User::factory()->create(['email' => 'real@y.com', 'email_verified_at' => null]);

    $url = URL::temporarySignedRoute('lukk.verification.verify', now()->addMinutes(60), [
        'id' => $user->getKey(),
        'hash' => sha1('changed@y.com'),
    ]);

    $this->getJson($url)->assertStatus(403);
    expect($user->fresh()->hasVerifiedEmail())->toBeFalse();
});

it('rejects a link for an unknown user id (403)', function () {
    $url = URL::temporarySignedRoute('lukk.verification.verify', now()->addMinutes(60), [
        'id' => 999999,
        'hash' => sha1('ghost@y.com'),
    ]);

    $this->getJson($url)->assertStatus(403);
});

it('is idempotent for an already-verified user (does not re-fire Verified)', function () {
    Event::fake([Verified::class]);
    $user = User::factory()->create(['email_verified_at' => now()]);

    $this->getJson(verifyUrl($user))->assertNoContent();

    Event::assertNotDispatched(Verified::class);
});

it('resends the verification link (202) pointing at lukk\'s signed route', function () {
    Notification::fake();
    $user = User::factory()->create(['email_verified_at' => null]);

    $this->withToken($user->startSession()->accessToken)
        ->postJson('/auth/email/verification-notification')
        ->assertStatus(202)
        ->assertJson(['status' => 'verification-link-sent']);

    Notification::assertSentTo($user, VerifyEmail::class, function (VerifyEmail $notification) use ($user) {
        // Building the mail exercises lukk's createUrlUsing override → the link targets our route.
        expect($notification->toMail($user)->actionUrl)->toContain('/auth/email/verify/');

        return true;
    });
});

it('does not resend for an already-verified user (202, nothing sent)', function () {
    Notification::fake();
    $user = User::factory()->create(['email_verified_at' => now()]);

    $this->withToken($user->startSession()->accessToken)
        ->postJson('/auth/email/verification-notification')
        ->assertStatus(202);

    Notification::assertNothingSent();
});

it('requires authentication to resend (401)', function () {
    $this->postJson('/auth/email/verification-notification')->assertStatus(401);
});

it('gates a route behind a verified email (409 unverified, 200 verified)', function () {
    Route::middleware(['auth:api', 'lukk.verified'])
        ->get('/_test/verified-only', fn () => response()->json(['ok' => true]));

    $unverified = User::factory()->create(['email_verified_at' => null]);
    $this->withToken($unverified->startSession()->accessToken)
        ->getJson('/_test/verified-only')
        ->assertStatus(409);

    // Second request as a different user — reset the memoized guard (per the CLAUDE.md gotcha).
    $this->app['auth']->forgetGuards();

    $verified = User::factory()->create(['email_verified_at' => now()]);
    $this->withToken($verified->startSession()->accessToken)
        ->getJson('/_test/verified-only')
        ->assertOk()
        ->assertJson(['ok' => true]);
});

it('blocks login for an unverified user when block_unverified_login is on', function () {
    config(['lukk.email_verification.block_unverified_login' => true]);
    User::factory()->create(['email' => 'u@y.com', 'email_verified_at' => null]);

    $this->postJson('/auth/login', ['email' => 'u@y.com', 'password' => 'password'])
        ->assertStatus(403);
});

it('allows a verified user to log in when block_unverified_login is on', function () {
    config(['lukk.email_verification.block_unverified_login' => true]);
    User::factory()->create(['email' => 'v@y.com', 'email_verified_at' => now()]);

    $this->postJson('/auth/login', ['email' => 'v@y.com', 'password' => 'password'])
        ->assertOk()
        ->assertJsonStructure(['access_token']);
});
