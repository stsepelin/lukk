<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers\Concerns;

use Lukk\Contracts\WebAuthnCeremony;

/**
 * Is a passkey assertion on this install worth two factors, or one?
 *
 * Only when user verification is REQUIRED. WebAuthn with UV is two factors in one gesture —
 * possession of the authenticator plus the PIN or biometric that unlocks it. Below `required` it is
 * possession alone: `web-auth/webauthn-lib`'s `CheckUserVerification::process()` returns before it
 * reads the UV flag unless the requirement is exactly `required`, so the assertion proves only that
 * someone held the key.
 *
 * Shared by BOTH passkey entry points on purpose. Gating login and leaving step-up open made the
 * login gate decorative: `POST /auth/confirm-passkey` mints the same `confirmation_token` the
 * password path does, so possession alone still bought `DELETE /auth/two-factor` and the enrolment
 * of another key — binding and removing an authenticator below the account's own assurance level
 * (NIST SP 800-63B §5.2.1). `routes/api.php` already says as much about the password gate: "it still
 * is not sufficient on its own, because a pin carrying `lukk.account` can earn its own confirmation."
 */
trait ChecksPasskeyAssurance
{
    private function passkeyIsSecondFactor(): bool
    {
        // Asked of the CEREMONY, not of config. Config is not the authority on what was enforced:
        // `WebAuthnCeremony` is an application singleton, so its setting is frozen at first
        // resolution and a later `config()` write (multi-tenant swapping, a test, an Octane worker)
        // does not reach it; and it is a declared swap seam, so a replacement may enforce something
        // else entirely. Both of those made a config read fail OPEN — the gate skipped an enrolled
        // second factor on the strength of a `required` nothing had applied.
        //
        // This also settles the per-guard question the previous version reasoned about at length:
        // whatever the ceremony was built from, it is the thing that ran.
        return app(WebAuthnCeremony::class)->verifiesUser();
    }
}
