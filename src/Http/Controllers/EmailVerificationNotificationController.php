<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lukk\Actions\SendEmailVerification;
use Lukk\Http\Concerns\PreventsCaching;

/**
 * (Re)send the verification link to the authenticated user. Always `202` (no-store);
 * a no-op if already verified. Throttled per IP (`lukk-email-verification`).
 */
class EmailVerificationNotificationController
{
    use PreventsCaching;

    public function __invoke(Request $request, SendEmailVerification $send): JsonResponse
    {
        $user = $request->user();

        if ($user instanceof MustVerifyEmail) {
            $send($user);
        }

        return $this->noStore(response()->json(['status' => 'verification-link-sent'], 202));
    }
}
