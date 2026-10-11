<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Lukk;
use Lukk\Passkeys\PasskeyAssurance;
use Lukk\Support\AuthenticationMethods;
use Lukk\Support\VerifiedToken;

/**
 * A password step-up mints the token that binds and removes authenticators, so it must meet "the
 * maximum AAL currently available in the subscriber account" (NIST SP 800-63B-4 §4.1.2.1).
 *
 * The password is one factor. §2.2.3 lets an AAL2 SESSION reauthenticate with one factor, so the
 * step-up is accepted when the presenting session was multi-factor (`amr` carries `mfa`), or when the
 * account has nothing stronger than the password. It is refused in a single-factor session on an
 * account with a confirmed second factor or a user-verifying passkey — the passkey path's own bar.
 *
 * A token without `amr` is treated as single-factor: nothing in it says otherwise, and the claim goes
 * missing in ordinary ways (a refresh on a schema without the `amr` column, `startSession()`, a co-issuer).
 * Such a session confirms with a user-verifying passkey, or signs in again with its second factor.
 *
 * Changing the password runs the same check: the new password REPLACES an authenticator, which is the
 * act §4.1.2.1 prices at the account's maximum AAL, and proving the current password is one factor.
 * `$field` names the input the refusal is reported on (`current_password` there), and `$message` the way
 * out that route offers: it takes no step-up confirmation, so only a fresh multi-factor sign-in satisfies it.
 */
class EnsurePasswordStepUpMeetsAccountLevel
{
    /**
     * @param  string  $field  the input the refusal is reported on
     * @param  string|null  $message  the refusal, naming the way out the calling route actually offers;
     *                                null for the step-up's own (a passkey confirmation is one there)
     */
    public function __invoke(Request $request, Authenticatable $user, string $field = 'password', ?string $message = null): void
    {
        $token = VerifiedToken::current($request);

        // No token at all is `Lukk::actingAs()`, which exists for tests: nothing was presented to judge.
        if ($token === null) {
            return;
        }

        // A token WITHOUT `amr` is not evidence of a multi-factor session. A refresh drops the claim where
        // the `amr` column is not migrated, and `startSession()` (a magic link, a social login) never stamps
        // one — so treating its absence as "old rule" let a password-only attacker wait one refresh.
        $amr = $token->claims->amr ?? null;

        if ((is_array($amr) && in_array(AuthenticationMethods::MULTI_FACTOR, $amr, true) && $this->recent($token->claims->auth_time ?? null))
            || ! $this->hasSecondFactor($user)) {
            return;
        }

        throw ValidationException::withMessages([$field => [
            $message ?? __('This account has a second factor. Confirm with a passkey that verifies you, or sign in again with your second factor first.'),
        ]]);
    }

    private function hasSecondFactor(Authenticatable $user): bool
    {
        // Only where this guard enforces it: with two-factor off, login never asks for the code, so no session
        // here could ever carry `mfa`, and counting the enrolled TOTP locked every step-up away for good.
        if (Lukk::enforcesTwoFactor() && method_exists($user, 'hasEnabledTwoFactor') && $user->hasEnabledTwoFactor()) {
            return true;
        }

        // The store first: building the WebAuthn ceremony validates the passkey config, and an account
        // with no passkeys must not have its password step-up fail on a passkey setting.
        // The cast only states the type; `&&` reads the flag's truthiness either way.
        return (bool) (Lukk::guardConfig()['features']['passkeys'] ?? false) // @pest-mutate-ignore: RemoveBooleanCast
            && app(PasskeyRepository::class)->credentialIdsFor($user->getAuthIdentifier()) !== []
            && app(PasskeyAssurance::class)->hasMultiFactorCredential($user);
    }

    /**
     * Whether the multi-factor sign-in is recent enough to vouch for this one-factor reauthentication.
     * §2.2.3 allows it within an AAL2 session, whose overall limit SHOULD be about 24 hours; `mfa` rides
     * every rotation for the whole refresh lifetime, so it is honoured only for `confirm.mfa_max_age`.
     */
    private function recent(mixed $authTime): bool
    {
        // A NumericDate, as OIDC Core §2 defines `auth_time`: a number — a fraction allowed, floored —
        // within the range a timestamp can mean, the bound the access verifier applies. Out of it, a
        // co-issuer's value made the integer cast warn into a 500.
        if (! is_numeric($authTime)) {
            return false;
        }

        $time = (float) $authTime;

        // Before the epoch is no sign-in at all. Nothing else needs a bound: the time stays a float, so no
        // cast can warn, and anything far in the future (INF included) is refused by the leeway below.
        if ($time < 0) {
            return false;
        }

        // Floored, and kept a float: a cast to int is what warned, and nothing here needs one.
        $signedIn = floor($time);

        $config = Lukk::guardConfig();
        $age = now()->getTimestamp() - $signedIn;

        // A sign-in in the future is not a recent one. lukk stores the real sign-in time with the family
        // (`SessionAuthentication`), but a co-issuer's token can carry any `auth_time`, and with no lower
        // bound a far-future one passed as brand new. Clock skew between servers gets the leeway.
        // Cast to float, too: a garbled override must fail closed (it reads as 0), not compare as a string,
        // and a "never" past the int range must not warn the way an int cast did.
        return $age >= -Lukk::leeway($config)
            && $age <= (float) ($config['confirm']['mfa_max_age'] ?? 86400);
    }
}
