<?php

declare(strict_types=1);

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Passkeys\DatabasePasskeyRepository;
use Lukk\Passkeys\PasskeyAssurance;
use Lukk\Support\AuthenticationMethods;
use Lukk\Support\NewPasskey;
use Lukk\Support\VerifiedPasskey;
use Lukk\Tests\Fixtures\FakeWebAuthnCeremony;
use Lukk\Tests\Fixtures\User;

uses()->group('passkeys');

beforeEach(fn () => app()->bind(WebAuthnCeremony::class, FakeWebAuthnCeremony::class));

/** A stored credential; `$multiFactor` models WebAuthn L3's `uvInitialized` via the fake's `+uv` marker. */
function credentialFor(User $user, string $id, bool $multiFactor): void
{
    app(PasskeyRepository::class)->store($user->getAuthIdentifier(), new NewPasskey($id, $multiFactor ? 'PUB+uv' : 'PUB', 0));
}

function assurance(): PasskeyAssurance
{
    return app(PasskeyAssurance::class);
}

describe('the amr values', function () {
    // Every value REGISTERED in the IANA "Authentication Method Reference Values" registry (RFC 8176),
    // so a standard consumer can read them. `webauthn`, which lukk used to emit, is not registered.

    it('names a password', function () {
        expect(AuthenticationMethods::password())->toBe(['pwd']);
    });

    it('names a passkey as possession plus presence, and adds mfa only when it was multi-factor', function () {
        expect(AuthenticationMethods::passkey(false))->toBe(['pop', 'user'])
            ->and(AuthenticationMethods::passkey(true))->toBe(['pop', 'user', 'mfa']);
    });

    it('calls a password plus a one-time code multi-factor', function () {
        // Two different categories — something you know, something you have.
        expect(AuthenticationMethods::withOneTimePassword(['pwd']))->toBe(['pwd', 'otp', 'mfa']);
    });

    it('does not call a single-factor passkey plus a one-time code multi-factor', function () {
        // Both are "something you have" (NIST SP 800-63B-4 §3.1.4, §3.1.6), and §2.2.1 requires a
        // password or biometric comparison for two single-factor authenticators to reach AAL2.
        expect(AuthenticationMethods::withOneTimePassword(['pop', 'user']))->toBe(['pop', 'user', 'otp']);
    });

    it('never carries a stray mfa from the first factor into a combination that is not', function () {
        expect(AuthenticationMethods::withOneTimePassword(['pop', 'user', 'mfa']))->toBe(['pop', 'user', 'otp']);
    });
});

describe('the highest level an account can reach', function () {
    // NIST SP 800-63B-4 §4.1.2.1: a step-up that binds or removes authenticators must authenticate at
    // "the maximum AAL currently available in the subscriber account".

    it('reaches AAL2 with a password, whatever its passkeys are', function () {
        $user = User::factory()->create();
        credentialFor($user, 'k', false);

        expect(assurance()->canReachMultiFactor($user))->toBeTrue()
            ->and(assurance()->requiredUserVerification($user))->toBe('required');
    });

    it('reaches AAL2 without a password through a multi-factor passkey', function () {
        $user = User::factory()->create(['password' => null]);
        credentialFor($user, 'single', false);
        credentialFor($user, 'multi', true);

        expect(assurance()->canReachMultiFactor($user))->toBeTrue();
    });

    it('stays at AAL1 with only single-factor passkeys and no password', function () {
        $user = User::factory()->create(['password' => null]);
        credentialFor($user, 'a', false);
        credentialFor($user, 'b', false);

        expect(assurance()->canReachMultiFactor($user))->toBeFalse()
            ->and(assurance()->requiredUserVerification($user))->toBe('preferred');
    });

    it('treats an empty password the same as none', function () {
        $user = User::factory()->create(['password' => '']);

        expect(assurance()->canReachMultiFactor($user))->toBeFalse();
    });

    it('treats a stored value the hasher cannot read as no password', function (string $placeholder) {
        // An import or SSO placeholder confirms nothing, so it must not raise the bar to a level the
        // account cannot reach.
        $user = User::factory()->create();
        $user->forceFill(['password' => $placeholder]);

        expect(assurance()->canReachMultiFactor($user))->toBeFalse()
            ->and(assurance()->requiredUserVerification($user))->toBe('preferred');
    })->with(['!', '*', 'imported-not-a-hash']);

    it('treats an empty or missing password as none even under a provider of its own', function (?string $none) {
        // A custom provider keeps an unrecognised value counted (it may verify a legacy format); an
        // empty one is no password under any provider.
        Auth::provider('custom', fn ($app, array $config) => new class($app['hash'], $config['model']) extends EloquentUserProvider {});
        config(['auth.providers.users.driver' => 'custom']);
        $user = User::factory()->create();
        $user->forceFill(['password' => $none]);

        expect(assurance()->canReachMultiFactor($user))->toBeFalse();
    })->with(['empty' => [''], 'null' => [null]]);

    it('counts the password when a custom hasher describes it in a shape of its own', function () {
        // `Hasher::info()` promises an array, not `password_get_info()`'s keys. One without
        // `algoName` says nothing about the value, so the stronger bar stands.
        $user = User::factory()->create();
        Hash::extend('opaque', fn () => new class extends BcryptHasher
        {
            public function info($hashedValue): array
            {
                return [];
            }
        });
        config(['hashing.driver' => 'opaque']);
        Hash::forgetDrivers();
        $user->forceFill(['password' => '!']);

        expect(assurance()->canReachMultiFactor($user))->toBeTrue();
    });

    it('lists only the account\'s own credentials for a step-up', function () {
        $user = User::factory()->create();
        credentialFor($user, 'mine', false);
        credentialFor(User::factory()->create(), 'theirs', false);

        expect(assurance()->credentialIdsFor($user))->toBe(['mine']);
    });
});

describe('whether one step-up meets that level', function () {
    it('accepts a multi-factor step-up on any account', function () {
        $user = User::factory()->create();

        expect(assurance()->permitsStepUp($user, new VerifiedPasskey($user->id, 'k', true)))->toBeTrue();
    });

    it('refuses a single-factor step-up on an account that can reach AAL2', function () {
        $user = User::factory()->create();

        expect(assurance()->permitsStepUp($user, new VerifiedPasskey($user->id, 'k', false)))->toBeFalse();
    });

    it('accepts a single-factor step-up on an account with nothing stronger', function () {
        // Refusing would strand it: no password to fall back on, and the passkey routes are the only
        // other way to mint a confirmation.
        $user = User::factory()->create(['password' => null]);
        credentialFor($user, 'k', false);

        expect(assurance()->permitsStepUp($user, new VerifiedPasskey($user->id, 'k', false)))->toBeTrue();
    });
});

it('hands the client a JSON list of credential ids even from a repository that keeps its keys', function () {
    // `PasskeyRepository::credentialIdsFor()` promises `array<int,string>`, not a list. A replacement
    // repository returning `[3 => 'a', 7 => 'b']` JSON-encodes as an OBJECT, and `allowCredentials`
    // stops being the array the WebAuthn client requires.
    $user = User::factory()->create();
    app()->instance(PasskeyRepository::class, new class extends DatabasePasskeyRepository
    {
        public function credentialIdsFor(int|string $userId): array
        {
            return [3 => 'a', 7 => 'b'];
        }
    });

    expect(json_encode(app(PasskeyAssurance::class)->credentialIdsFor($user)))->toBe('["a","b"]');
});
