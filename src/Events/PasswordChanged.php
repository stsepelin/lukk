<?php

declare(strict_types=1);

namespace Lukk\Events;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * A signed-in user changed their own password, having proven the current one.
 *
 * Distinct from Laravel's `PasswordReset`, which fires for the forgot-password flow — that one
 * proves control of the email address, this one proves knowledge of the existing password. Apps
 * usually want to react to both but say different things: "your password was changed" versus "your
 * password was reset". Carries the user, since unlike the reset path there is always a resolved one.
 */
class PasswordChanged
{
    public function __construct(public readonly Authenticatable $user) {}
}
