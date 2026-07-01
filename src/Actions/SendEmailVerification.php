<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\MustVerifyEmail;

/**
 * (Re)send the verification email via the user's own notification (whose URL lukk
 * points at the signed verify route). A no-op for an already-verified user.
 */
class SendEmailVerification
{
    public function __invoke(MustVerifyEmail $user): void
    {
        if (! $user->hasVerifiedEmail()) {
            $user->sendEmailVerificationNotification();
        }
    }
}
