<?php

declare(strict_types=1);

namespace Lukk\Tests;

/**
 * Boots the suite with the registration feature OFF (the default suite enables it), so a
 * test can prove the `/auth/register` route is gated and absent when the flag is false.
 */
class RegistrationDisabledTestCase extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('lukk.features.registration', false);
    }
}
