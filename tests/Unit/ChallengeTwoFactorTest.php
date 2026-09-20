<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\ChallengeTwoFactor;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

uses()->group('two-factor');

function challengeRefusal(Closure $call): ValidationException
{
    try {
        $call();
    } catch (ValidationException $e) {
        return $e;
    }

    throw new RuntimeException('Expected the second factor to be refused.');
}

it('refuses a valid code for a secret that was never confirmed', function () {
    // Enrolment writes the secret before the user proves they hold it; until `confirmed_at` is set
    // it is not a second factor, and a code for it signs nobody in.
    $secret = app(TwoFactorProvider::class)->generateSecret();
    $user = User::factory()->create();
    $user->forceFill(['two_factor_secret' => Crypt::encryptString($secret), 'two_factor_confirmed_at' => null])->save();

    $e = challengeRefusal(fn () => app(ChallengeTwoFactor::class)($user->getKey(), app(Google2FA::class)->getCurrentOtp($secret), null));

    expect($e->errors())->toBe(['code' => ['The provided two-factor code was invalid.']]);
});

it('refuses an account that no longer exists', function () {
    expect(challengeRefusal(fn () => app(ChallengeTwoFactor::class)(999999, '123456', null))->errors())->toHaveKey('code');
});

it('refuses a user model with no two-factor support at all', function () {
    // A provider may return any Authenticatable; one without `hasEnabledTwoFactor` has no second
    // factor to pass, and must not be asked for one.
    $users = Mockery::mock(UserProvider::class);
    $users->allows('retrieveById')->andReturn(new GenericUser(['id' => 1]));
    $action = new ChallengeTwoFactor($users, app(TwoFactorProvider::class));

    expect(challengeRefusal(fn () => $action(1, '123456', null))->errors())->toHaveKey('code');
});
