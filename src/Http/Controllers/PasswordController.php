<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Lukk\Actions\ChangePassword;
use Lukk\Actions\EnsurePasswordStepUpMeetsAccountLevel;
use Lukk\Contracts\TokenVerifier;
use Lukk\Http\Concerns\PreventsCaching;
use Lukk\Http\Controllers\Concerns\ResolvesAuthenticatedUser;
use Lukk\Http\Controllers\Concerns\ResolvesCurrentFamily;
use Lukk\Http\Requests\ChangePasswordRequest;

/**
 * Change the authenticated user's password. `update` re-verifies the current password, sets the
 * new one, revokes every OTHER session, and fires `PasswordChanged`.
 *
 * Throttled on the step-up budget (`lukk-confirm`) because it checks the same secret, and a wrong
 * current password counts toward the same `confirm` lockout.
 */
class PasswordController
{
    use PreventsCaching;
    use ResolvesAuthenticatedUser;
    use ResolvesCurrentFamily;

    public function update(
        ChangePasswordRequest $request,
        ChangePassword $change,
        TokenVerifier $verifier,
        EnsurePasswordStepUpMeetsAccountLevel $meetsAccountLevel,
    ): JsonResponse {
        $validated = $request->validated();

        // The new password replaces an authenticator, so the session must meet the account's maximum AAL
        // (NIST SP 800-63B-4 §4.1.2.1) — the bar the password step-up applies. Before the current password
        // is checked: a refusal spends no lockout attempt and says nothing about the password.
        // Its own message: this route takes no step-up confirmation, so "confirm with a passkey" would
        // point at something that cannot satisfy it here — only a fresh multi-factor sign-in does.
        $meetsAccountLevel($request, $this->authenticated($request), 'current_password', __(
            'This account has a second factor. Sign in again with your second factor, or with a passkey that verifies you, then change the password.',
        ));

        $change(
            $this->authenticated($request),
            // Both validated as strings (`string`, and the `Password` rule refuses anything else).
            (string) $validated['current_password'], // @pest-mutate-ignore: RemoveStringCast
            (string) $validated['password'], // @pest-mutate-ignore: RemoveStringCast
            // The session to KEEP — see the trait for why it comes from the verified token.
            $this->currentFamilyId($request, $verifier),
        );

        return $this->noStore(response()->json(['status' => 'password-changed'], 200));
    }
}
