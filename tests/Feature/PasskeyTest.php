<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\FinishPasskeyLogin;
use Lukk\Actions\StartPasskeyRegistration;
use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Events\PasskeyCloneDetected;
use Lukk\Models\Lockout;
use Lukk\Models\Passkey;
use Lukk\Passkeys\PasskeyChallengeStore;
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

it('renders 422, not a 500, for a non-scalar credential id', function () {
    // `credential` was typed only as `array`, so `credential.id` could be an array or object and
    // `FinishPasskeyLogin`'s `(string) $id` raised an ErrorException — a 500 from an UNAUTHENTICATED
    // caller, against this package's own rule that malformed input is a 422. The ceremony id comes
    // free from the public `login-options` route, so the whole path is pre-auth.
    $id = $this->postJson('/auth/passkeys/login-options')->assertOk()->json('ceremony_id');

    foreach ([['a'], ['k' => 'v']] as $hostile) {
        $this->postJson('/auth/passkeys/login', ['ceremony_id' => $id, 'credential' => ['id' => $hostile]])
            ->assertStatus(422);
    }
})->group('passkeys');

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

    expect(claims($access)->amr)->toBe(['webauthn'])
        ->and(claims($access)->sub)->toBe((string) $user->id);
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
    ])->assertStatus(422)->assertJsonValidationErrors(['credential' => 'That passkey does not belong to you.']);
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
        app('auth')->forgetGuards();
        $this->withToken($access)->postJson('/auth/confirm-passkey', [
            'ceremony_id' => 'nope', 'credential' => ['id' => 'cred-1'],
        ])->assertStatus(422);
    }

    app('auth')->forgetGuards();
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

it('prunes passkeys whose user no longer exists', function () {
    // Nothing else ever removes these: a passkey has no expiry, so `lukk:prune` had nothing to do
    // with them, and erasure only reaches an account deleted through lukk's own route. A row deleted
    // directly, or by a cascade elsewhere, left the credential id, the human-chosen device name and
    // a last-used timestamp behind permanently.
    $living = User::factory()->create();
    $doomed = User::factory()->create();
    storePasskey($living->getKey(), 'cred-living');
    storePasskey($doomed->getKey(), 'cred-orphan');

    User::query()->whereKey($doomed->getKey())->delete();   // deleted OUTSIDE lukk's route

    command('lukk:prune')->assertSuccessful();

    expect(Passkey::whereKey('cred-orphan')->exists())->toBeFalse()
        ->and(Passkey::whereKey('cred-living')->exists())->toBeTrue();
});

it('prunes on a pre-0.6 schema that has no guard column', function () {
    // The column went into the EXISTING create migration, so every install that already ran it has
    // no such column until they act on UPGRADE.md. Naming it anyway broke two different ways:
    // MySQL/PostgreSQL throw `Unknown column` — and `lukk:prune` is `->daily()`, so that takes the
    // refresh-token and lockout sweeps down every night — while SQLite degrades a double-quoted
    // identifier matching no column to a STRING LITERAL, so `"guard" is null` is false for every row
    // and the sweep silently deletes nothing, forever, while reporting success.
    $user = User::factory()->create();
    app(PasskeyRepository::class)->store($user->getKey(), new NewPasskey('live-cred', 'cose', 0), 'Live');
    app(PasskeyRepository::class)->store(999999, new NewPasskey('dead-cred', 'cose', 0), 'Orphan');

    Schema::table('passkeys', fn (Blueprint $table) => $table->dropColumn('guard'));

    expect(app(PasskeyRepository::class)->pruneOrphaned())->toBe(1)
        ->and(Passkey::find('dead-cred'))->toBeNull()
        ->and(Passkey::find('live-cred'))->not->toBeNull();
});

it('refuses a duplicate credential id as a validation failure, not a database error', function () {
    // `credential_id` is globally unique (the PK) but the assertion lookup is guard-scoped, so the
    // registration pre-check has to ask a wider question than that lookup answers. It didn't, so a
    // duplicate reached the unique index: a 500 rather than a 422, and an existence oracle across
    // the guard boundary. lukk supports only `none` attestation, so the id is client-chosen.
    $user = User::factory()->create();
    app(PasskeyRepository::class)->store($user->getKey(), new NewPasskey('taken', 'cose', 0), 'Existing');

    expect(app(PasskeyRepository::class)->existsByCredentialId('taken'))->toBeTrue()
        ->and(app(PasskeyRepository::class)->existsByCredentialId('free'))->toBeFalse();

    // NOTE: under a single guard `scoped()` applies no filter, so this half cannot tell a scoped
    // check from an unscoped one. The property that matters lives in AccountDeletionMultiGuardTest.
});

it('still lets a verified user sign in with a passkey when block_unverified_login is on', function () {
    // The gate is about verification status, not the authenticator: the two-factor fix must not
    // have narrowed the passkey path for an account that IS verified.
    config(['lukk.email_verification.block_unverified_login' => true]);
    $user = User::factory()->create(['email_verified_at' => now()]);
    storePasskey($user->id, 'cred-verified', 0);

    $start = $this->postJson('/auth/passkeys/login-options')->json();
    $this->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-verified', 'sign_count' => 1],
    ])->assertOk()->assertJsonStructure(['access_token']);
});

/** Present `cred-1` with the given counter to a fresh sign-in ceremony. */
function presentPasskey(int $signCount): TestResponse
{
    $start = test()->postJson('/auth/passkeys/login-options')->json();

    return test()->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-1', 'sign_count' => $signCount],
    ]);
}

it('rejects a sign count that merely repeats the stored one', function (int $stored) {
    // WebAuthn L3 §6.1.1: once a non-zero counter has been seen, anything not strictly greater is
    // the clone signal — an equal count included.
    Event::fake([PasskeyCloneDetected::class]);
    storePasskey(User::factory()->create()->id, 'cred-1', $stored);

    presentPasskey($stored)
        ->assertStatus(422)
        ->assertJsonValidationErrors(['credential' => 'The passkey could not be verified.']);

    Event::assertDispatched(PasskeyCloneDetected::class);
})->with([
    'the first non-zero count' => [1],
    'a later count' => [10],
]);

it('advances the stored counter to the one just presented', function (int $stored, int $presented) {
    // The ratchet the clone check compares against: left behind, a replay of an older assertion
    // would pass it.
    storePasskey(User::factory()->create()->id, 'cred-1', $stored);

    presentPasskey($presented)->assertOk();

    expect(Passkey::findOrFail('cred-1')->sign_count)->toBe($presented);
})->with([
    'from zero' => [0, 7],
    'from a count' => [5, 9],
]);

it('refuses a credential id that is not a string, rather than failing on its type', function () {
    // Reachable when the action is called directly, without the request that types `credential.id`.
    $ceremony = app(PasskeyChallengeStore::class)->putForCeremony(app(PasskeyChallengeStore::class)->generate());

    expect(fn () => app(FinishPasskeyLogin::class)($ceremony, ['id' => 123]))->toThrow(ValidationException::class);
});

/** Register `$credentialId` for a fresh user through the HTTP ceremony. */
function registerPasskey(string $credentialId): TestResponse
{
    $access = User::factory()->create()->startSession()->accessToken;
    $headers = confirmedHeaders($access);
    $challenge = test()->withToken($access)->withHeaders($headers)
        ->postJson('/auth/passkeys/registration-options')->json('challenge');

    return test()->withToken($access)->withHeaders($headers)->postJson('/auth/passkeys', [
        'credential' => ['challenge' => $challenge, 'id' => $credentialId, 'public_key' => 'PUB', 'sign_count' => 0],
    ]);
}

it('registers a credential id of exactly 255 characters, the column width, and refuses a longer one', function () {
    registerPasskey(str_repeat('a', 255))->assertNoContent();
    app('auth')->forgetGuards();

    registerPasskey(str_repeat('b', 256))
        ->assertStatus(422)
        ->assertJsonValidationErrors(['credential' => 'The passkey could not be registered.']);
});

it('names the new credential after the email, or the id when there is none', function () {
    $user = User::factory()->create(['email' => 'ada@example.test']);
    $access = $user->startSession()->accessToken;
    $this->withToken($access)->withHeaders(confirmedHeaders($access))
        ->postJson('/auth/passkeys/registration-options')
        ->assertJsonPath('user', 'ada@example.test');

    $anonymous = new class extends User
    {
        protected $table = 'users';

        public function getEmailAttribute(): ?string
        {
            return null;
        }
    };
    $model = $anonymous::query()->findOrFail($user->getKey());

    expect(app(StartPasskeyRegistration::class)($model)['user'])->toBe((string) $user->getKey());
});
