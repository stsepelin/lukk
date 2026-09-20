<?php

declare(strict_types=1);

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\TwoFactor\Google2FaTotpProvider;
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

/** The provider on a cache the test can inspect, with the given drift window. */
function totpOn(Repository $cache, int $window = 1): Google2FaTotpProvider
{
    return new Google2FaTotpProvider(app(Google2FA::class), $cache, ['issuer' => 'Lukk', 'window' => $window]);
}

it('marks a used code under a key bound to both the secret and the code', function () {
    // Bound to the secret so two accounts that happen to share a code in one step don't lock each
    // other out, and namespaced so the marker can't collide with an application's own cache keys.
    $cache = Cache::store('array');
    $secret = totp()->generateSecret();
    $code = app(Google2FA::class)->getCurrentOtp($secret);

    expect(totpOn($cache)->verify($secret, $code))->toBeTrue()
        ->and($cache->get('lukk:2fa:used:'.hash('sha256', $secret.'|'.$code)))->toBeTrue();
});

it('holds the replay marker for the code\'s whole validity band, and no longer', function () {
    // ±window steps of 30 s: with window 1 a code stays valid across 90 s, so a marker that lapsed
    // sooner would let the same code through again inside that band.
    $this->freezeSecond();
    $cache = Cache::store('array');
    $secret = totp()->generateSecret();
    $code = app(Google2FA::class)->getCurrentOtp($secret);
    $key = 'lukk:2fa:used:'.hash('sha256', $secret.'|'.$code);

    totpOn($cache)->verify($secret, $code);

    $this->travel(89)->seconds();
    expect($cache->has($key))->toBeTrue();

    $this->travel(2)->seconds();
    expect($cache->has($key))->toBeFalse();
});
