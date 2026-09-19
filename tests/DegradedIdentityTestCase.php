<?php

declare(strict_types=1);

namespace Lukk\Tests;

/**
 * The identity keys at their worst before boot: `path` and `guard` null (an env variable that is not
 * set) and `username` empty (an `LUKK_USERNAME=` line with nothing after it). Pre-boot, because the
 * routes read `path` and `guard` while they register.
 */
class DegradedIdentityTestCase extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('lukk.path', null);
        $app['config']->set('lukk.guard', null);
        $app['config']->set('lukk.username', '');
    }
}
