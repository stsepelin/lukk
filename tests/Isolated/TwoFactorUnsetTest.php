<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Crypt;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Tests\Fixtures\User;
use Lukk\Tests\TwoFactorUnsetTestCase;
use PragmaRX\Google2FA\Google2FA;

uses(TwoFactorUnsetTestCase::class)->group('multi-guard', 'two-factor');

function routeMounted(string $method, string $uri): bool
{
    return collect(app('router')->getRoutes())
        ->contains(fn ($route) => $route->uri() === $uri && in_array($method, $route->methods(), true));
}

it('mounts the challenge redemption on every guard when two_factor is unset', function () {
    expect(routeMounted('POST', 'auth/two-factor-challenge'))->toBeTrue()
        ->and(routeMounted('POST', 'admin/auth/two-factor-challenge'))->toBeTrue();
});

it('does not mount two-factor management when two_factor is unset', function () {
    // Redemption keeps an already-enrolled account able to sign in. Enrolling a NEW factor is a
    // feature the install never switched on.
    expect(routeMounted('POST', 'auth/two-factor'))->toBeFalse()
        ->and(routeMounted('POST', 'auth/two-factor/confirm'))->toBeFalse();
});

it('challenges an enrolled account and lets it finish signing in', function () {
    $user = User::factory()->create();
    $secret = app(TwoFactorProvider::class)->generateSecret();
    $user->forceFill(['two_factor_secret' => Crypt::encryptString($secret), 'two_factor_confirmed_at' => now()])->save();

    $challenge = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->assertJsonMissingPath('access_token')->json('challenge_token');

    app('auth')->forgetGuards();

    $this->postJson('/auth/two-factor-challenge', [
        'challenge_token' => $challenge,
        'code' => app(Google2FA::class)->getCurrentOtp($secret),
    ])->assertOk()->assertJsonStructure(['access_token']);
});

it('still signs in an account that never enrolled', function () {
    $user = User::factory()->create();

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->assertJsonStructure(['access_token']);
});
