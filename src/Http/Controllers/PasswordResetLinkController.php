<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Lukk\Actions\SendPasswordResetLink;
use Lukk\Http\Concerns\PreventsCaching;
use Lukk\Http\Requests\ForgotPasswordRequest;

/**
 * Request a password-reset link. Always returns a generic `200` (no-store) — the response is
 * identical whether or not the email is registered, so it can't be used to enumerate accounts.
 * Throttled per IP (`lukk-password-reset`); the broker also throttles per email.
 */
class PasswordResetLinkController
{
    use PreventsCaching;

    public function __invoke(ForgotPasswordRequest $request, SendPasswordResetLink $send): JsonResponse
    {
        $send($request->validated()['email']);

        return $this->noStore(response()->json(['status' => 'password-reset-link-sent'], 200));
    }
}
