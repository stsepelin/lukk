<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\FinishPasskeyLogin;
use Lukk\Actions\StartPasskeyRegistration;
use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Events\PasskeyCloneDetected;
use Lukk\Models\Lockout;
use Lukk\Models\Passkey;
use Lukk\Passkeys\PasskeyChallengeStore;
use Lukk\Support\Abilities;
use Lukk\Support\NewPasskey;
use Lukk\Tests\Fixtures\FakeWebAuthnCeremony;
use Lukk\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

uses()->group('passkeys');

beforeEach(fn () => app()->bind(WebAuthnCeremony::class, FakeWebAuthnCeremony::class));

/**
 * `$uvInitialized` models WebAuthn L3's credential-record flag: TRUE once the credential has shown
 * user verification to this RP. Only then may an assertion's UV flag count as a second factor (§4).
 */
function storePasskey(int|string $userId, string $credentialId, int $signCount = 0, bool $uvInitialized = false): void
{
    app(PasskeyRepository::class)->store($userId, new NewPasskey($credentialId, $uvInitialized ? 'PUB+uv' : 'PUB', $signCount));
}

/** Run a passkey login ceremony with the fake authenticator, optionally reporting user verification. */
function passkeyLogin(object $test, string $credentialId, bool $uv, int $signCount = 1): TestResponse
{
    $start = $test->postJson('/auth/passkeys/login-options')->assertOk()->json();

    return $test->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => $credentialId, 'sign_count' => $signCount, 'uv' => $uv],
    ]);
}

/** Run a passkey STEP-UP ceremony through its own options route, as the client is expected to. */
function passkeyStepUp(object $test, string $access, string $credentialId, bool $uv, int $signCount = 1): TestResponse
{
    $start = $test->withToken($access)->postJson('/auth/confirm-passkey/options')->assertOk()->json();

    return $test->withToken($access)->postJson('/auth/confirm-passkey', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => $credentialId, 'sign_count' => $signCount, 'uv' => $uv],
    ]);
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

it('logs in passwordlessly with a passkey and stamps the registered amr for it', function () {
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-1', 0);

    $start = $this->postJson('/auth/passkeys/login-options')->assertOk()->json();

    $access = $this->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-1', 'sign_count' => 1],
    ])->assertOk()->json('access_token');

    // RFC 8176 registered values: proof of possession of a key, plus the user-presence test every
    // assertion passes. `webauthn` was never a registered value, so no standard consumer could read it.
    expect(claims($access)->amr)->toBe(['pop', 'user'])
        ->and(claims($access)->sub)->toBe((string) $user->id);
});

it('keeps a passkey amr across refreshes, rather than downgrading it to pwd', function () {
    // The `['pwd']` assertions elsewhere cannot see a rotation that stamps a CONSTANT: every one of
    // them survives a refresh that hardcodes `['pwd']`, which is the fail-open direction — a
    // phishing-resistant session silently re-described as a password one, and now durable for the
    // family's whole life rather than a single access_ttl.
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-refresh', 0);

    $start = $this->postJson('/auth/passkeys/login-options')->assertOk()->json();
    $pair = $this->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-refresh', 'sign_count' => 1],
    ])->assertOk()->json();

    app('auth')->forgetGuards();
    $rotated = $this->postJson('/auth/refresh', ['refresh_token' => $pair['refresh_token']])->assertOk();

    expect(claims($rotated->json('access_token'))->amr)->toBe(['pop', 'user']);

    // TWICE. The first refreshed token's claim comes from the row being consumed, so a rotation that
    // never PERSISTS `amr` still looks right after one hop and only shows up on the second.
    app('auth')->forgetGuards();
    $again = $this->postJson('/auth/refresh', ['refresh_token' => $rotated->json('refresh_token')])->assertOk();

    expect(claims($again->json('access_token'))->amr)->toBe(['pop', 'user']);
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
    // A MULTI-FACTOR passkey: this account has a password, so AAL2 is within its reach and a
    // single-factor step-up is refused (NIST SP 800-63B-4 §4.1.2.1). The property pinned here — an
    // earned token satisfies the confirm gate — is unchanged; only the precondition was made honest.
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-1', 0, uvInitialized: true);
    $access = $user->startSession()->accessToken;

    $start = $this->postJson('/auth/passkeys/login-options')->json();

    $confirmation = $this->withToken($access)->postJson('/auth/confirm-passkey', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-1', 'sign_count' => 1, 'uv' => true],
    ])->assertOk()->json('confirmation_token');

    // The earned token satisfies the confirm gate on a sensitive route.
    $this->withToken($access)->withHeaders(['X-Lukk-Confirmation' => $confirmation])
        ->postJson('/auth/passkeys/registration-options')->assertOk();
});

it('rejects a passkey confirmation with another user’s passkey', function () {
    // Multi-factor, so the assertion itself verifies and the OWNERSHIP check is what refuses it —
    // with a single-factor key the user-verification requirement would refuse it first, and this
    // test would pass without ever reaching the check it exists for.
    $owner = User::factory()->create();
    storePasskey($owner->id, 'cred-1', 0, uvInitialized: true);
    $access = User::factory()->create()->startSession()->accessToken;

    $start = $this->postJson('/auth/passkeys/login-options')->json();

    $this->withToken($access)->postJson('/auth/confirm-passkey', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-1', 'sign_count' => 1, 'uv' => true],
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

it('challenges for the second factor when user verification is not required', function () {
    // The skip used to be unconditional. It is sound ONLY under `user_verification: required`, where
    // WebAuthn is two factors in one gesture — possession plus the PIN or biometric that unlocks it.
    // `config/lukk.php` offers `preferred` as a supported setting, and beneath `required`
    // `web-auth/webauthn-lib`'s `CheckUserVerification` returns early without ever reading the UV
    // flag. So on such an install whoever held the authenticator got a full session without the TOTP
    // the user deliberately enrolled — and could then spend it on `DELETE /auth/two-factor`.
    config(['lukk.passkeys.user_verification' => 'preferred']);
    $user = User::factory()->create();
    $user->forceFill([
        'two_factor_secret' => Crypt::encryptString('SECRETSECRETSECR'),
        'two_factor_confirmed_at' => now(),
    ])->save();
    storePasskey($user->id, 'cred-2fa', 0);

    $start = $this->postJson('/auth/passkeys/login-options')->assertOk()->json();
    $response = $this->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-2fa', 'sign_count' => 1],
    ])->assertOk();

    $response->assertJsonStructure(['two_factor', 'challenge_token'])->assertJsonMissingPath('access_token');
});

/** Enrol and confirm a real second factor. Named apart from the multi-guard suite's own helper. */
function confirmSecondFactorFor(object $model): string
{
    $secret = app(TwoFactorProvider::class)->generateSecret();

    $model->forceFill([
        'two_factor_secret' => Crypt::encryptString($secret),
        'two_factor_confirmed_at' => now(),
    ])->save();

    return $secret;
}

it('records the passkey, not a password, when a passkey login completes a second factor', function () {
    // The challenge branch hands a WebAuthn login to the 2FA controller, which hardcoded
    // `['pwd','otp']` — so a passkey login was recorded as a password one. On a PASSWORDLESS account
    // that asserts a credential the account does not have, and the same release makes `amr` durable,
    // so the false claim now rides every rotation for the family's whole life. Both directions are
    // wrong: an RP gating on `pwd` ("the knowledge factor was presented") is fail-open, and one
    // gating on `webauthn` for phishing resistance refuses a session that was in fact stronger.
    config(['lukk.passkeys.user_verification' => 'preferred']);
    $user = User::factory()->create(['password' => null]);
    $secret = confirmSecondFactorFor($user);
    storePasskey($user->id, 'cred-2fa-amr', 0);

    $start = $this->postJson('/auth/passkeys/login-options')->assertOk()->json();
    $challenge = $this->postJson('/auth/passkeys/login', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-2fa-amr', 'sign_count' => 1],
    ])->assertOk()->json('challenge_token');

    app('auth')->forgetGuards();
    $pair = $this->postJson('/auth/two-factor-challenge', [
        'challenge_token' => $challenge,
        'code' => app(Google2FA::class)->getCurrentOtp($secret),
    ])->assertOk()->json();

    // `pop user otp` and NOT `mfa`: two possession factors (NIST SP 800-63B-4 §2.2.1).
    expect(claims($pair['access_token'])->amr)->toBe(['pop', 'user', 'otp']);

    // And it survives rotation, like every other amr.
    app('auth')->forgetGuards();
    $rotated = $this->postJson('/auth/refresh', ['refresh_token' => $pair['refresh_token']])->assertOk();
    expect(claims($rotated->json('access_token'))->amr)->toBe(['pop', 'user', 'otp']);
});

it('leaves a password-less account a way to step up under preferred', function () {
    // The gate that refuses possession-only step-up must not strand the accounts this package
    // itself creates. `ConfirmPassword` calls `validateCredentials`, which returns false whenever
    // the column is empty — so for a passkey-only, SSO or invited-not-yet-set user the "use your
    // password instead" advice is impossible to follow, and `IssuesConfirmationToken` has only these
    // two callers. Refusing both leaves no way to mint a `reauth` token at all: no enrolling a
    // SECOND passkey (the only self-service recovery from a lost authenticator), no managing 2FA, no
    // changing a password, no export or erasure. `features.password_reset` is off by default, so
    // there is not even a reset escape hatch. One lost key and the account is unrecoverable.
    config(['lukk.passkeys.user_verification' => 'preferred']);
    $user = User::factory()->create(['password' => null]);
    $pair = $user->startSession();
    storePasskey($user->id, 'cred-only-way', 0);

    $start = $this->withToken($pair->accessToken)->postJson('/auth/passkeys/login-options')->assertOk()->json();
    $this->withToken($pair->accessToken)->postJson('/auth/confirm-passkey', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-only-way', 'sign_count' => 1],
    ])->assertOk()->assertJsonStructure(['confirmation_token']);
});

/*
 * Per-ASSERTION assurance (WebAuthn L3 §4 `uvInitialized`, §6.2.3; NIST SP 800-63B-4 §2.2.1, §4.1.2.1).
 *
 * An assertion is two factors in one gesture only when its UV flag is set AND the stored credential
 * is already `uvInitialized` — "When this is FALSE, including an authentication ceremony where it
 * would be updated to TRUE, the UV flag MUST NOT be relied upon as an authentication factor." Not
 * when CONFIG says `required`: config describes what was asked for, the assertion is what happened.
 */

it('skips an enrolled second factor for a multi-factor assertion', function () {
    $user = User::factory()->create();
    confirmSecondFactorFor($user);
    storePasskey($user->id, 'cred-mfa', 0, uvInitialized: true);

    $pair = passkeyLogin($this, 'cred-mfa', uv: true)->assertOk()->json();

    expect($pair)->toHaveKey('access_token')
        ->and(claims($pair['access_token'])->amr)->toBe(['pop', 'user', 'mfa']);
});

it('does not trust the UV flag of a credential that has never shown user verification', function () {
    // The attack the spec's rule exists for: steal a key that had no PIN, set a PIN on it yourself,
    // and every assertion now carries UV. The credential was registered without it, so it is not
    // `uvInitialized`, and that UV flag is worth nothing — the enrolled TOTP must still be asked for.
    $user = User::factory()->create();
    confirmSecondFactorFor($user);
    storePasskey($user->id, 'cred-pin-added-later', 0, uvInitialized: false);

    passkeyLogin($this, 'cred-pin-added-later', uv: true)
        ->assertOk()->assertJsonStructure(['two_factor', 'challenge_token'])->assertJsonMissingPath('access_token');
});

it('challenges for the second factor when this assertion did not verify the user', function () {
    $user = User::factory()->create();
    confirmSecondFactorFor($user);
    storePasskey($user->id, 'cred-no-uv-now', 0, uvInitialized: true);

    passkeyLogin($this, 'cred-no-uv-now', uv: false)
        ->assertOk()->assertJsonStructure(['two_factor', 'challenge_token'])->assertJsonMissingPath('access_token');
});

it('records a single-factor passkey as possession and presence only', function () {
    $user = User::factory()->create();
    storePasskey($user->id, 'cred-sf', 0);

    $access = passkeyLogin($this, 'cred-sf', uv: false)->assertOk()->json('access_token');

    expect(claims($access)->amr)->toBe(['pop', 'user']);
});

it('does not call a single-factor passkey plus a TOTP multi-factor', function () {
    // Both are "something you have" (NIST SP 800-63B-4 §3.1.4, §3.1.6), and §2.2.1 requires two
    // single-factor authenticators to include a password or biometric comparison to reach AAL2. So
    // no `mfa`: an RP gating on it must not be told this session cleared a bar it did not.
    $user = User::factory()->create(['password' => null]);
    $secret = confirmSecondFactorFor($user);
    storePasskey($user->id, 'cred-sf-otp', 0);

    $challenge = passkeyLogin($this, 'cred-sf-otp', uv: false)->assertOk()->json('challenge_token');

    app('auth')->forgetGuards();
    $access = $this->postJson('/auth/two-factor-challenge', [
        'challenge_token' => $challenge,
        'code' => app(Google2FA::class)->getCurrentOtp($secret),
    ])->assertOk()->json('access_token');

    expect(claims($access)->amr)->toBe(['pop', 'user', 'otp']);
});

it('accepts a multi-factor passkey step-up on any account', function () {
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    storePasskey($user->id, 'cred-step-mfa', 0, uvInitialized: true);

    passkeyStepUp($this, $access, 'cred-step-mfa', uv: true)->assertOk()->assertJsonStructure(['confirmation_token']);
});

it('refuses a single-factor passkey step-up when the account can reach a higher assurance level', function () {
    // NIST SP 800-63B-4 §4.1.2.1: binding an authenticator requires authentication at "the maximum
    // AAL currently available in the subscriber account". A password puts AAL2 within reach, so a
    // possession-only step-up is below the account's own level — and the token it would mint
    // unlocks binding and removing authenticators.
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    storePasskey($user->id, 'cred-step-sf', 0);

    // The ceremony enforces the `required` it asked for, so a non-UV assertion fails verification.
    passkeyStepUp($this, $access, 'cred-step-sf', uv: false)->assertStatus(422)->assertJsonMissingPath('confirmation_token');
});

it('refuses a step-up whose UV flag comes from a credential that never showed user verification', function () {
    // The case only lukk's own check can catch: the authenticator DID report UV, so the ceremony's
    // `required` is satisfied — but the credential is not `uvInitialized`, so per WebAuthn L3 §4 the
    // flag "MUST NOT be relied upon". A stolen no-PIN key with a PIN set by the thief looks like this.
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    storePasskey($user->id, 'cred-pin-later', 0, uvInitialized: false);

    passkeyStepUp($this, $access, 'cred-pin-later', uv: true)->assertStatus(403)->assertJsonMissingPath('confirmation_token');
});

it('refuses a single-factor step-up when another of the account\'s passkeys is multi-factor', function () {
    // Password-less, but a phone passkey with user verification puts AAL2 within reach — so a stolen
    // backup key with no PIN, plus a stolen session, must not be enough to bind the thief's own key.
    $user = User::factory()->create(['password' => null]);
    $access = $user->startSession()->accessToken;
    storePasskey($user->id, 'cred-phone', 0, uvInitialized: true);
    storePasskey($user->id, 'cred-backup-key', 0, uvInitialized: false);

    // AAL2 is within reach via the phone passkey, so `required` is asked for and enforced.
    passkeyStepUp($this, $access, 'cred-backup-key', uv: false)->assertStatus(422);
});

it('accepts a single-factor step-up when the account has nothing stronger', function () {
    // Password-less with only single-factor credentials: the account's maximum AAL is AAL1, which is
    // what this assertion proves. Refusing would strand it — no password to fall back on, and these
    // are the only routes that mint a confirmation token — while protecting nothing the account has.
    $user = User::factory()->create(['password' => null]);
    $access = $user->startSession()->accessToken;
    storePasskey($user->id, 'cred-only', 0, uvInitialized: false);

    passkeyStepUp($this, $access, 'cred-only', uv: false)->assertOk()->assertJsonStructure(['confirmation_token']);
});

it('does not let an enrolled TOTP raise a single-factor step-up, and takes no code here at all', function () {
    // A TOTP is also possession, so it cannot lift a single-factor step-up to AAL2 — and accepting
    // codes on this route opened a second, unthrottled TOTP oracle that ignored the 2FA lockout.
    // The account is password-less with only single-factor credentials, so its maximum is AAL1 and
    // the passkey alone suffices; a `code` sent alongside is simply not read.
    $user = User::factory()->create(['password' => null]);
    confirmSecondFactorFor($user);
    $access = $user->startSession()->accessToken;
    storePasskey($user->id, 'cred-sf-2fa', 0, uvInitialized: false);

    $start = $this->withToken($access)->postJson('/auth/confirm-passkey/options')->assertOk()->json();
    $this->withToken($access)->postJson('/auth/confirm-passkey', [
        'ceremony_id' => $start['ceremony_id'],
        'credential' => ['challenge' => $start['options']['challenge'], 'id' => 'cred-sf-2fa', 'sign_count' => 1, 'uv' => false],
        'code' => '000000',
    ])->assertOk();
});

it('asks the authenticator to verify the user only when the account needs it', function () {
    // WebAuthn L3 §5.8.6: an RP that needs user verification sets `required`. When the account can
    // reach AAL2 the step-up needs it; otherwise asking would just fail keys that cannot do it.
    $withPassword = User::factory()->create();
    storePasskey($withPassword->id, 'cred-a', 0);
    $options = $this->withToken($withPassword->startSession()->accessToken)
        ->postJson('/auth/confirm-passkey/options')->assertOk()->json('options');

    expect($options['userVerification'])->toBe('required')
        ->and($options['allowCredentials'])->toBe(['cred-a']);

    app('auth')->forgetGuards();
    $passwordless = User::factory()->create(['password' => null]);
    storePasskey($passwordless->id, 'cred-b', 0);
    $options = $this->withToken($passwordless->startSession()->accessToken)
        ->postJson('/auth/confirm-passkey/options')->assertOk()->json('options');

    expect($options['userVerification'])->toBe('preferred');
});

it('requires authentication to ask for step-up options', function () {
    $this->postJson('/auth/confirm-passkey/options')->assertStatus(401);
});
