<?php

declare(strict_types=1);

use Lukk\Contracts\TwoFactorProvider;
use PragmaRX\Google2FA\Google2FA;

uses()->group('two-factor');

function totp(): TwoFactorProvider
{
    return app(TwoFactorProvider::class);
}

it('generates a 160-bit base32 secret', function () {
    expect(totp()->generateSecret())->toBeString()->toHaveLength(32);
});

it('builds an otpauth provisioning uri', function () {
    $uri = totp()->otpauthUri('user@example.com', totp()->generateSecret());

    expect($uri)->toStartWith('otpauth://totp/');
});

it('verifies a current code and rejects a wrong one', function () {
    $secret = totp()->generateSecret();
    $code = app(Google2FA::class)->getCurrentOtp($secret);

    expect(totp()->verify($secret, $code))->toBeTrue();
    expect(totp()->verify($secret, '000000'))->toBeFalse();
});

it('rejects reuse of a code within its window (replay)', function () {
    $secret = totp()->generateSecret();
    $code = app(Google2FA::class)->getCurrentOtp($secret);

    expect(totp()->verify($secret, $code))->toBeTrue();
    expect(totp()->verify($secret, $code))->toBeFalse();
});
