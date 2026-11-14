<?php

declare(strict_types=1);

namespace Lukk\Tests;

/**
 * The identity keys at their worst before boot: `path` and `guard` null (an env variable that is not
 * set) and `username` empty (an `LUKK_USERNAME=` line with nothing after it), and the feature flags
 * that default on, missing. Pre-boot, because the routes read all of them while they register.
 */
class DegradedIdentityTestCase extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('lukk.path', null);
        $app['config']->set('lukk.guard', null);
        $app['config']->set('lukk.username', '');

        // The feature flags that default ON, as a config cached before the key existed leaves them.
        $app['config']->set('lukk.features.logout_all', null);
        $app['config']->set('lukk.features.account_deletion', null);
        $app['config']->set('lukk.features.change_password', null);
        // And the switch for the routes themselves, which defaults on the same way.
        $app['config']->set('lukk.routes', null);
    }
}
