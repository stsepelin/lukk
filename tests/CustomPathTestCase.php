<?php

declare(strict_types=1);

namespace Lukk\Tests;

/**
 * `lukk.path` set to something other than the default, before boot: the routes read it while they
 * register, so setting it in a test would be too late to move anything.
 */
class CustomPathTestCase extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('lukk.path', 'account/auth');
    }
}
