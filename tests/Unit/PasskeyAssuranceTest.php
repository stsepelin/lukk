<?php

declare(strict_types=1);

use Lukk\Http\Controllers\Concerns\ChecksPasskeyAssurance;
use Lukk\Lukk;

uses()->group('passkeys');

function assurance(): object
{
    return new class
    {
        use ChecksPasskeyAssurance;

        public function secondFactor(): bool
        {
            return $this->passkeyIsSecondFactor();
        }
    };
}

it('treats a passkey as a second factor only when user verification is required', function (mixed $configured, bool $expected) {
    config(['lukk.passkeys.user_verification' => $configured]);

    expect(assurance()->secondFactor())->toBe($expected);
})->with([
    'required' => ['required', true],
    'preferred' => ['preferred', false],
    'discouraged' => ['discouraged', false],
    'a typo' => ['Required', false],
    'a non-string' => [['required'], false],
    // Unset reads as required, matching what `SpomkyWebAuthnCeremony` itself defaults to. The two
    // defaults are a pair; a test pins that so they cannot drift apart unnoticed.
    'unset' => [null, true],
]);

it('reads user verification from the same place the ceremony enforces it', function () {
    // The gate and the ceremony must never disagree. The ceremony is an application SINGLETON built
    // from the GLOBAL block, so a per-guard override does not reach it — and a gate that read the
    // per-guard value would skip the second factor on the strength of a `required` the ceremony
    // never applied. That is the fail-open direction, and it is the exact shape CLAUDE.md records
    // for `features.abilities` / `gate_auth_routes`, running the other way.
    config([
        'lukk.passkeys.user_verification' => 'preferred',
        'lukk.guards.admin.passkeys.user_verification' => 'required',
    ]);

    Lukk::onGuard('admin', function () {
        expect(assurance()->secondFactor())->toBeFalse();
    });
});
