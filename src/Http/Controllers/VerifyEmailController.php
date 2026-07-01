<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Lukk\Actions\VerifyEmail;
use Lukk\Contracts\EmailVerificationResponse;
use Lukk\Http\Requests\VerifyEmailRequest;

/**
 * Verify an email from a signed link. The `signed` middleware guarantees the URL is
 * untampered and unexpired; the request confirms the `{id}`/`{hash}` binding. Marks
 * the user verified (idempotent) and returns the EmailVerificationResponse — a
 * redirect to your SPA verify page, or a 204 for a JSON client.
 */
class VerifyEmailController
{
    public function __invoke(VerifyEmailRequest $request, VerifyEmail $verify): EmailVerificationResponse
    {
        /** @var MustVerifyEmail $user Guaranteed non-null by the request's authorize(). */
        $user = $request->verifiable();

        $verify($user);

        return app(EmailVerificationResponse::class);
    }
}
