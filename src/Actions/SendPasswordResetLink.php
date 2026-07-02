<?php

declare(strict_types=1);

namespace Lukk\Actions;

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
        Password::broker($this->broker)->sendResetLink(['email' => $email]);
    }
}
