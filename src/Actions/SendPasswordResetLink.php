<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;

/**
 * Send a password-reset link via Laravel's password broker. The broker status is
 * intentionally **ignored** — the endpoint returns the same response whether or not the
 * email exists (and whether or not it's throttled), so it can't enumerate accounts.
 */
class SendPasswordResetLink
{
    public function __construct(private readonly ?string $broker = null) {}

    public function __invoke(string $email): void
    {
        $status = Password::broker($this->broker)->sendResetLink(['email' => $email]);

        // The RESPONSE was already constant; the timing was not. A known address costs a
        // `Hash::make` (the broker hashes the reset token before storing it) plus the notification;
        // an unknown one returns immediately. The broker's 200ms Timebox pads a fast path up to its
        // budget but cannot claw back an overrun, and at Laravel's default BCRYPT_ROUNDS=12 bcrypt
        // costs ~70-120ms ON TOP of it — measured as fully disjoint distributions, so a single
        // request classified an address.
        //
        // So burn the equivalent work on the miss, exactly as the login path does for an unknown
        // user. This does not equalize the mail send: queue the notification (the usual advice
        // anyway) or a synchronous SMTP transport re-opens the gap.
        if ($status !== Password::RESET_LINK_SENT) {
            Hash::make('lukk-timing-equalizer');
        }
    }
}
