<?php

declare(strict_types=1);

namespace Lukk\Tests;

/**
 * `features.logout_all` switched OFF globally but back ON for the `admin` guard.
 *
 * One configuration exercises both halves: the flag is honoured at all (the default guard loses the
 * route), and it is read through the guard's resolved config rather than the global block (the admin
 * guard keeps it). Set before boot, because routes are registered during boot.
 */
class LogoutAllDisabledTestCase extends MultiGuardTestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('lukk.features.logout_all', false);
        $app['config']->set('lukk.guards.admin.features', ['logout_all' => true]);
    }
}
