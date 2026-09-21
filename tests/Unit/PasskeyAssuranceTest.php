<?php

declare(strict_types=1);

use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Http\Controllers\Concerns\ChecksPasskeyAssurance;
use Lukk\Lukk;
use Lukk\Tests\Fixtures\FakeWebAuthnCeremony;

uses()->group('passkeys');

beforeEach(function () {
    // The real ceremony refuses to construct without these, and this file resolves it on purpose —
    // the gate now asks the ceremony what it enforces rather than reading config behind its back.
    config([
        'lukk.passkeys.rp_id' => 'example.test',
        'lukk.passkeys.origins' => ['https://example.test'],
    ]);
});

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
    // The gate asks the CEREMONY, which is a singleton built from config at resolution — so the
    // config has to be in place before it is built, exactly as it is at boot in a real application.
    app()->forgetInstance(WebAuthnCeremony::class);

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
    app()->forgetInstance(WebAuthnCeremony::class);

    Lukk::onGuard('admin', function () {
        expect(assurance()->secondFactor())->toBeFalse();
    });
});

it('asks the ceremony what it enforces, so a stale singleton cannot make it lie', function () {
    // `WebAuthnCeremony` is an application SINGLETON: its user-verification setting is frozen at
    // first resolution, while a config read happens on every call. Change the config afterwards —
    // which multi-tenant config swapping does per tenant, under Octane or a queue worker — and the
    // gate would skip a confirmed second factor on the strength of a `required` the ceremony never
    // applied. Same outcome as the per-guard divergence, reached by time instead of by guard.
    config(['lukk.passkeys.user_verification' => 'preferred']);
    app(WebAuthnCeremony::class); // resolve it, freezing `preferred`

    config(['lukk.passkeys.user_verification' => 'required']);

    expect(assurance()->secondFactor())->toBeFalse();
});

it('believes a rebound ceremony over the config it does not read', function () {
    // The other half: `WebAuthnCeremony` is a declared swap seam. A replacement that does not verify
    // the user makes `config('lukk.passkeys.user_verification')` a statement about a value nobody
    // enforces — and it fails OPEN, which is structurally the `scope`/`pin`/`TokenIssuer` seam
    // incident this package has already had twice.
    config(['lukk.passkeys.user_verification' => 'required']);
    app()->instance(WebAuthnCeremony::class, new class extends FakeWebAuthnCeremony
    {
        public function verifiesUser(): bool
        {
            return false;
        }
    });

    expect(assurance()->secondFactor())->toBeFalse();
});
