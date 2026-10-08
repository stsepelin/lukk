<?php

declare(strict_types=1);

namespace Lukk\Events;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * A TOTP authenticator was confirmed, so sign-in now asks for it.
 *
 * NIST SP 800-63B-4 §4.1.2.1 requires notifying the subscriber, through a channel independent of
 * the request, when an authenticator is bound, and removal (§4.6) warrants the same. lukk sends no
 * mail: listen for this and tell the user, so a stolen session cannot change their authenticators
 * unnoticed.
 */
class TwoFactorAuthenticationConfirmed
{
    public function __construct(
        public readonly Authenticatable $user,
    ) {}
}
