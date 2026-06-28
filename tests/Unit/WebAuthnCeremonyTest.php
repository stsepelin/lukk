<?php

declare(strict_types=1);

use Lukk\Passkeys\SpomkyWebAuthnCeremony;

uses()->group('passkeys');

// The ceremony fails loud rather than fall back to weak origin/RP validation.

it('refuses to construct without an rp_id', function () {
    expect(fn () => new SpomkyWebAuthnCeremony([
        'rp_id' => '',
        'rp_name' => 'Example',
        'origins' => ['https://app.example.com'],
        'user_verification' => 'preferred',
    ]))->toThrow(InvalidArgumentException::class);
});

it('refuses to construct with no allowed origins', function () {
    expect(fn () => new SpomkyWebAuthnCeremony([
        'rp_id' => 'example.com',
        'rp_name' => 'Example',
        'origins' => [],
        'user_verification' => 'preferred',
    ]))->toThrow(InvalidArgumentException::class);
});
