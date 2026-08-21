<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lukk\Actions\ChangePassword;
use Lukk\Contracts\TokenVerifier;
use Lukk\Http\Concerns\PreventsCaching;
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

    public function update(ChangePasswordRequest $request, ChangePassword $change, TokenVerifier $verifier): JsonResponse
    {
        // The caller's own family, read from their bearer token — this is the session to KEEP.
        // Taken from the verified token rather than from the request, so it can't be pointed at
        // someone else's session (or at a family the caller doesn't own) to spare it from the sweep.
        $claims = $verifier->verify((string) $request->bearerToken());

        $change(
            $request->user(),
            (string) $request->input('current_password'),
            (string) $request->input('password'),
            isset($claims->fid) ? (string) $claims->fid : null,
        );

        return $this->noStore(response()->json(['status' => 'password-changed'], 200));
    }
}
