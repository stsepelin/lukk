<?php

declare(strict_types=1);

use Lukk\Actions\RevokeSession;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\LoginResponse;
use Lukk\Contracts\TokenVerifier;
use Lukk\Support\TokenPair;
use Lukk\Tests\Fixtures\User;

/**
 * These lock in the customization seams advertised in the README: an app should
 * be able to rebind any contract and have the package use the replacement,
 * without editing package code.
 */
it('lets an app reshape login output by rebinding the LoginResponse contract', function () {
    app()->bind(LoginResponse::class, fn ($app, array $params) => new class($params['pair']) implements LoginResponse
    {
        public function __construct(private TokenPair $pair) {}

        public function toResponse($request)
        {
            return response()->json(['custom' => true, 'at' => $this->pair->accessToken]);
        }
    });

    User::factory()->create(['email' => 'swap@y.com']);

    $this->postJson('/auth/login', ['email' => 'swap@y.com', 'password' => 'password'])
        ->assertOk()
        ->assertJson(['custom' => true])
        ->assertJsonMissing(['refresh_token']);
});

it('lets an app swap the Denylist implementation behind the contract', function () {
    $fake = new class implements Denylist
    {
        /** @var array<int,string> */
        public array $revokedFamilies = [];

        public function revokeJti(string $jti, int $ttlSeconds): void {}

        public function revokeFamily(string $familyId, int $ttlSeconds): void
        {
            $this->revokedFamilies[] = $familyId;
        }

        public function has(string $type, string $id): bool
        {
            return false;
        }

        public function hasAny(array $types): bool
        {
            return false;
        }
    };

    app()->instance(Denylist::class, $fake);

    app(RevokeSession::class)('fam-xyz');

    expect($fake->revokedFamilies)->toBe(['fam-xyz']);
});

it('authenticates requests with a rebound TokenVerifier, not only logout', function () {
    // The seam the customization guide names for changing how tokens are validated. The guard driver and
    // the step-up family binding each built `FirebaseTokenVerifier` themselves, so a stricter verifier
    // decided logout and nothing else: every `auth:` request and every confirmation skipped it.
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;

    $this->withToken($access)->deleteJson('/auth/sessions/others')->assertSuccessful();

    $this->app->bind(TokenVerifier::class, fn () => new class implements TokenVerifier
    {
        public function verify(#[SensitiveParameter] string $jwt): ?object
        {
            return null;
        }
    });
    $this->app['auth']->forgetGuards();

    $this->withToken($access)->deleteJson('/auth/sessions/others')->assertUnauthorized();
});

it('binds a step-up confirmation to the family a rebound TokenVerifier reports', function () {
    // Both halves of the binding read the presenting family through the contract. With a verifier that
    // admits the token but reports no family, the confirmation is minted unbound rather than bound to a
    // family the application's verifier never vouched for.
    $user = User::factory()->create();
    $access = $user->startSession()->accessToken;
    $real = app(TokenVerifier::class);

    $this->app->bind(TokenVerifier::class, fn () => new class($real) implements TokenVerifier
    {
        public function __construct(private TokenVerifier $inner) {}

        public function verify(#[SensitiveParameter] string $jwt): ?object
        {
            $claims = $this->inner->verify($jwt);

            if ($claims !== null) {
                $claims->fid = 'family-the-verifier-reports';
            }

            return $claims;
        }
    });
    $this->app['auth']->forgetGuards();

    $token = $this->withToken($access)->postJson('/auth/confirm-password', ['password' => 'password'])
        ->assertOk()->json('confirmation_token');

    expect(app(ChallengeToken::class)->familyOf('reauth', $token))->toBe('family-the-verifier-reports');
});

it('refuses an array cache store in production, where revocation would be invisible', function () {
    // Everything that makes an ALREADY-ISSUED credential stop working lives in this cache. An array
    // store is per-process: a revoked token stays valid on every other worker, and the single-use
    // guarantees are not guarantees. It fails silently, which is what makes it worth refusing.
    app()->detectEnvironment(fn () => 'production');
    config(['lukk.denylist_store' => 'array']);

    expect(fn () => app(Denylist::class))
        ->toThrow(RuntimeException::class, 'cannot use the [ArrayStore] cache store');
});

it('leaves the array store alone outside production, where it is the right default', function () {
    // lukk's own suite runs on it.
    config(['lukk.denylist_store' => 'array']);

    expect(app(Denylist::class))->toBeInstanceOf(Denylist::class);
});
