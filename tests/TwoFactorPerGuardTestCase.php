<?php

declare(strict_types=1);

namespace Lukk\Tests;

/**
 * `features.two_factor` OFF globally and ON for the `admin` guard, set before boot because routes are
 * registered during boot.
 *
 * The admin mount has to read the ADMIN guard's flag. Read from the global block, an enrolled admin is
 * challenged at login and has no route to answer it on.
 */
class TwoFactorPerGuardTestCase extends MultiGuardTestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('lukk.features.two_factor', false);
        $app['config']->set('lukk.guards.admin.features', ['two_factor' => true]);
    }
}
