<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers\Concerns;

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
        // The GLOBAL block, deliberately — not `Lukk::guardConfig()`, which is the rule everywhere
        // else in this package. This value is not a policy flag lukk decides; it is a question about
        // what the CEREMONY actually enforced, and the ceremony is an application singleton built
        // from the global block (`LukkServiceProvider::registerPasskeys()`), so a per-guard override
        // never reaches it. Reading the per-guard value here would let a guard set `required`, skip
        // the enrolled second factor on the strength of it, and have the ceremony run `preferred`
        // and never look at the UV flag — fail open, which is the one direction that must not happen.
        //
        // If `WebAuthnCeremony` is ever made guard-scoped, this read moves with it, in the same
        // change. A test pins the two together.
        //
        // An UNRECOGNISED value is not `required`, so the caller's stricter path runs — fail closed.
        // An UNSET one reads as `required`, which is safe only because `SpomkyWebAuthnCeremony`
        // defaults the same way: those two defaults are a pair and must be changed together.
        return (config('lukk.passkeys.user_verification') ?? 'required') === 'required';
    }
}
