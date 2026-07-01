<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Auth\Events\Verified;
use Illuminate\Contracts\Auth\MustVerifyEmail;

/**
 * Mark a user's email verified and fire Laravel's `Verified` event (so the host
 * app's listeners work unchanged). Idempotent: an already-verified user is a no-op,
 * so a double-clicked link doesn't re-mark or re-fire.
 */
class VerifyEmail
{
    public function __invoke(MustVerifyEmail $user): void
    {
        if ($user->hasVerifiedEmail()) {
            return;
        }

        $user->markEmailAsVerified();

        event(new Verified($user));
    }
}
