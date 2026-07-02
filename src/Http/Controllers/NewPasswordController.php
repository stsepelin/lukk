<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Lukk\Actions\ResetPassword;
use Lukk\Http\Concerns\PreventsCaching;
use Lukk\Http\Requests\ResetPasswordRequest;

/**
 * Complete a password reset with the emailed token + a new password. On success the password
 * is updated, `PasswordReset` fires, and (by default) every existing session is revoked. An
 * invalid / expired token renders a `422`. Throttled per IP (`lukk-password-reset`).
 */
class NewPasswordController
{
    use PreventsCaching;

    public function __invoke(ResetPasswordRequest $request, ResetPassword $reset): JsonResponse
    {
        $reset($request->validated());

        return $this->noStore(response()->json(['status' => 'password-reset'], 200));
    }
}
