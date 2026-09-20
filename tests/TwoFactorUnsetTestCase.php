<?php

declare(strict_types=1);

namespace Lukk\Tests;

/**
 * `features.two_factor` resolving to null — an unset `env()` — on every guard, set before boot because
 * routes are registered during boot.
 *
 * Login fails closed on an unset flag and challenges an enrolled account, so the redemption route has to
 * mount on the same predicate; a challenge with nowhere to answer it is a lockout.
 */
class TwoFactorUnsetTestCase extends MultiGuardTestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('lukk.features.two_factor', null);
    }
}
