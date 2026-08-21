<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Lukk\Actions\ChangePassword;
use Lukk\Contracts\TokenVerifier;
use Lukk\Http\Concerns\PreventsCaching;
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
    use ResolvesCurrentFamily;

    public function update(ChangePasswordRequest $request, ChangePassword $change, TokenVerifier $verifier): JsonResponse
    {
        $validated = $request->validated();

        $change(
            $request->user(),
            (string) $validated['current_password'],
            (string) $validated['password'],
            // The session to KEEP — see the trait for why it comes from the verified token.
            $this->currentFamilyId($request, $verifier),
        );

        return $this->noStore(response()->json(['status' => 'password-changed'], 200));
    }
}
