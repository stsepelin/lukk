<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Support\Facades\Password;
use Illuminate\Support\Timebox;

/**
 * Send a password-reset link via Laravel's password broker. The broker status is
 * intentionally **ignored** — the endpoint returns the same response whether or not the
 * email exists (and whether or not it's throttled), so it can't enumerate accounts.
 */
class SendPasswordResetLink
{
    public function __construct(
        private readonly ?string $broker = null,
        private readonly int $timeboxMicros = 1_000_000,
    ) {}

    public function __invoke(string $email): void
    {
        // The RESPONSE was already constant; the TIMING is what a Timebox makes constant too.
        //
        // The broker pads every outcome to its own 200 ms box, but a hit also hashes the reset token
        // and dispatches the notification, which at Laravel's default BCRYPT_ROUNDS=12 can run past
        // 200 ms — and a Timebox never claws back an overrun. lukk used to "equalize" a miss by hashing
        // once AFTER the broker returned, which put that derivation OUTSIDE the padded box: a miss then
        // cost 200 ms plus a hash and a hit ~200 ms in total. Measured 460 ms against 259 ms, never
        // overlapping — equal work, unequal time, and the slower side flipped rather than closed.
        //
        // So the whole call is boxed, with a budget above the broker's box plus one derivation plus
        // the dispatch. A synchronous SMTP transport can still overrun any budget: queue the reset
        // notification, which is the usual advice anyway.
        app(Timebox::class)->call(
            fn () => Password::broker($this->broker)->sendResetLink(['email' => $email]),
            $this->timeboxMicros,
        );
    }
}
