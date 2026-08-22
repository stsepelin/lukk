<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Events\PasskeyCloneDetected;
use Lukk\Models\Lockout;
use Lukk\Support\Abilities;
use Lukk\Support\NewPasskey;
use Lukk\Tests\Fixtures\FakeWebAuthnCeremony;
use Lukk\Tests\Fixtures\User;

uses()->group('passkeys');

beforeEach(fn () => app()->bind(WebAuthnCeremony::class, FakeWebAuthnCeremony::class));

function storePasskey(int|string $userId, string $credentialId, int $signCount = 0): void
{
    app(PasskeyRepository::class)->store($userId, new NewPasskey($credentialId, 'PUB', $signCount));
}

it('registers a passkey (auth + confirmation)', function () {
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    $headers = confirmedHeaders($access);

    $challenge = $this->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys/registration-options')->assertOk()->json('challenge');

    $this->withToken($access)->withHeaders($headers)->postJson('/auth/passkeys', [
        'name' => 'My Key',
        'credential' => ['challenge' => $challenge, 'id' => 'cred-1', 'public_key' => 'PUB', 'sign_count' => 0],
    ])->assertNoContent();

    expect(app(PasskeyRepository::class)->findByCredentialId('cred-1'))->not->toBeNull();
});

it('requires confirmation to register a passkey', function () {
    $access = User::factory()->create()->startSession()->accessToken;

    $this->withToken($access)->postJson('/auth/passkeys/registration-options')->assertStatus(423);
});

it('rejects registration with an invalid attestation', function () {
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    $headers = confirmedHeaders($access);
    $this->withToken($access)->withHeaders($headers)->postJson('/auth/passkeys/registration-options')->assertOk();

    $this->withToken($access)->withHeaders($headers)->postJson('/auth/passkeys', [
        'credential' => ['challenge' => 'tampered', 'id' => 'cred-1'],
    ])->assertStatus(422);
});

it('rejects registration with no pending challenge', function () {
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;

    $this->withToken($access)->withHeaders(confirmedHeaders($access))->postJson('/auth/passkeys', [
        'credential' => ['challenge' => 'x', 'id' => 'cred-1'],
    ])->assertStatus(422);
});

it('logs in passwordlessly with a passkey and stamps amr=webauthn', function () {
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-1', 0);

    $start = $this->postJson('/auth/passkeys/login-options')->assertOk()->json();

    $access = $this->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-1', 'sign_count' => 1],
    ])->assertOk()->json('access_token');

    expect(verifier()->verify($access)->amr)->toBe(['webauthn'])
        ->and(verifier()->verify($access)->sub)->toBe((string) $user->id);
});

it('rejects a replayed assertion (the challenge is single-use)', function () {
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-1', 0);
    $start = $this->postJson('/auth/passkeys/login-options')->json();
    $credential = ['challenge' => $start['options']['challenge'], 'id' => 'cred-1', 'sign_count' => 1];

    $this->postJson('/auth/passkeys/login', ['ceremony_id' => $start['ceremony_id'], 'credential' => $credential])->assertOk();
    $this->postJson('/auth/passkeys/login', ['ceremony_id' => $start['ceremony_id'], 'credential' => $credential])->assertStatus(422);
});

it('rejects a tampered assertion', function () {
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-1', 0);
    $start = $this->postJson('/auth/passkeys/login-options')->json();

    $this->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => 'tampered', 'id' => 'cred-1'],
    ])->assertStatus(422);
});

it('rejects an unknown credential', function () {
    $start = $this->postJson('/auth/passkeys/login-options')->json();

    $this->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'ghost', 'sign_count' => 1],
    ])->assertStatus(422);
});

it('rejects a sign-count regression (cloned authenticator) and fires an event', function () {
    Event::fake([PasskeyCloneDetected::class]);
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-1', 10);
    $start = $this->postJson('/auth/passkeys/login-options')->json();

    $this->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-1', 'sign_count' => 5],
    ])->assertStatus(422);

    Event::assertDispatched(PasskeyCloneDetected::class);
});

it('does not flag a zero sign count (synced passkeys)', function () {
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-1', 0);
    $start = $this->postJson('/auth/passkeys/login-options')->json();

    $this->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-1', 'sign_count' => 0],
    ])->assertOk();
});

it('earns a step-up confirmation with a passkey', function () {
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-1', 0);
    $access = $user->startSession()->accessToken;

    $start = $this->postJson('/auth/passkeys/login-options')->json();

    $confirmation = $this->withToken($access)->postJson('/auth/confirm-passkey', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-1', 'sign_count' => 1],
    ])->assertOk()->json('confirmation_token');

    // The earned token satisfies the confirm gate on a sensitive route.
    $this->withToken($access)->withHeaders(['X-Lukk-Confirmation' => $confirmation])
        ->postJson('/auth/passkeys/registration-options')->assertOk();
});

it('rejects a passkey confirmation with another user’s passkey', function () {
    $owner = User::factory()->create();
    storePasskey($owner->id, 'cred-1', 0);
    $access = User::factory()->create()->startSession()->accessToken;

    $start = $this->postJson('/auth/passkeys/login-options')->json();

    $this->withToken($access)->postJson('/auth/confirm-passkey', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-1', 'sign_count' => 1],
    ])->assertStatus(422);
});

it('rejects a passkey login with a missing or non-array credential', function () {
    $this->postJson('/auth/passkeys/login', ['ceremony_id' => 'x'])
        ->assertStatus(422)->assertJsonValidationErrorFor('credential');

    $this->postJson('/auth/passkeys/login', ['ceremony_id' => 'x', 'credential' => 'not-an-array'])
        ->assertStatus(422)->assertJsonValidationErrorFor('credential');
});

it('lists and deletes the user’s passkeys', function () {
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-1', 0);
    $access = $user->startSession()->accessToken;

    $this->withToken($access)->getJson('/auth/passkeys')
        ->assertOk()
        ->assertJsonStructure(['passkeys' => [['id', 'name', 'last_used_at']]]);

    $this->withToken($access)->withHeaders(confirmedHeaders($access))->deleteJson('/auth/passkeys/cred-1')->assertNoContent();

    expect(app(PasskeyRepository::class)->findByCredentialId('cred-1'))->toBeNull();
});

it('rejects registering an already-registered credential', function () {
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    $headers = confirmedHeaders($access);

    storePasskey($user->id, 'cred-dup'); // credential_id is globally unique

    $challenge = $this->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys/registration-options')->assertOk()->json('challenge');

    // A valid attestation whose credential id collides with an existing one is a
    // clean 422, not a raw duplicate-key DB error.
    $this->withToken($access)->withHeaders($headers)->postJson('/auth/passkeys', [
        'credential' => ['challenge' => $challenge, 'id' => 'cred-dup', 'public_key' => 'PUB', 'sign_count' => 0],
    ])->assertStatus(422);
});

it('meters confirm-passkey on the shared confirm budget', function () {
    // DoS/CPU metering, not brute-force defence: an assertion is a signature, not a guessable
    // secret. That is also why it is not gated by the confirm lockout.
    config(['lukk.rate_limits.confirm.max_attempts' => 2]);
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-1', 0);
    $access = $user->startSession()->accessToken;

    foreach (range(1, 2) as $i) {
        $this->app['auth']->forgetGuards();
        $this->withToken($access)->postJson('/auth/confirm-passkey', [
            'ceremony_id' => 'nope', 'credential' => ['id' => 'cred-1'],
        ])->assertStatus(422);
    }

    $this->app['auth']->forgetGuards();
    $this->withToken($access)->postJson('/auth/confirm-passkey', [
        'ceremony_id' => 'nope', 'credential' => ['id' => 'cred-1'],
    ])->assertStatus(429);
});

it('refuses a credential id too long for its own primary key', function () {
    // WebAuthn L3 permits a 1023-byte raw id (1364 base64url chars) but `credential_id` is the
    // varchar(255) primary key: a longer one is a 500 on MySQL strict, or a silent truncation that
    // no later assertion can match — locking the user out of the credential they just registered.
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    $headers = confirmedHeaders($access);

    // Complete a REAL ceremony — the challenge has to match, or the request fails before the length
    // guard and this test proves nothing.
    $challenge = $this->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys/registration-options')->assertOk()->json('challenge');

    $this->withToken($access)->withHeaders($headers)->postJson('/auth/passkeys', [
        'name' => 'Too long',
        'credential' => ['challenge' => $challenge, 'id' => str_repeat('A', 300), 'public_key' => 'PUB', 'sign_count' => 0],
    ])->assertStatus(422);

    expect(app(PasskeyRepository::class)->findByCredentialId(str_repeat('A', 300)))->toBeNull();
});

it('clears a confirm lock on a successful passkey assertion', function () {
    // "Consecutive" was only honoured for the password authenticator: a passkey-primary user could
    // carry confirm failures planted by a token thief and lock on their next typo.
    config(['lukk.features.lockout' => true, 'lukk.rate_limits.confirm.max_attempts' => 500]);
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-lock', 0);
    app(LockoutRepository::class)->recordFailure('confirm', (string) $user->getKey(), 'api');

    $start = $this->postJson('/auth/passkeys/login-options')->json();
    $this->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-lock', 'sign_count' => 1],
    ])->assertOk();

    expect(Lockout::where('purpose', 'confirm')->exists())->toBeFalse();
});

it('applies block_unverified_login to passkey login, like the password path', function () {
    // The passkey path minted a session straight off the credential row, so it never ran the gate.
    // Reachable in any app that nulls `email_verified_at` on an email change: the user still has a
    // registered passkey and walks past the block that refuses their password.
    config(['lukk.features.email_verification' => true, 'lukk.email_verification.block_unverified_login' => true]);
    $user = User::factory()->create(['email_verified_at' => null]);
    storePasskey($user->id, 'cred-unverified', 0);

    $start = $this->postJson('/auth/passkeys/login-options')->json();
    $this->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-unverified', 'sign_count' => 1],
    ])->assertStatus(403);
});

it('refuses passkey login for a user deleted since registering the credential', function () {
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-orphan', 0);
    $user->delete();

    $start = $this->postJson('/auth/passkeys/login-options')->json();
    $this->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-orphan', 'sign_count' => 1],
    ])->assertStatus(401);

    expect(DB::table('refresh_tokens')->count())->toBe(0);
});

it('refuses a pinned token the passkey list', function () {
    // It enumerates the account's second factors — credential ids, the human-chosen device names,
    // last-use timestamps. Target selection for a social-engineering step, and the write side of the
    // same objects is already behind `lukk.account`.
    $user = User::factory()->create();
    storePasskey($user->getKey(), 'cred-abc');

    $pat = start()($user->getKey(), [], ['ci.deploy']);
    $this->withToken($pat->accessToken)->getJson('/auth/passkeys')->assertStatus(403);

    app('auth')->forgetGuards();

    // ...an ordinary session still reads it, and so does a pinned token that asked.
    $this->withToken($user->startSession()->accessToken)->getJson('/auth/passkeys')->assertOk();
    app('auth')->forgetGuards();
    $allowed = start()($user->getKey(), [], ['ci.deploy', Abilities::ACCOUNT]);
    $this->withToken($allowed->accessToken)->getJson('/auth/passkeys')->assertOk();
});
