<?php

declare(strict_types=1);

namespace Lukk\Tests;

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;

/**
 * A verify-only service: `lukk.routes` off, with every feature still on. Pre-boot, because the routes
 * and the notification links are wired while the provider boots.
 *
 * The two notification callbacks are static, so whatever an earlier test's boot left in them is cleared
 * first — otherwise "not wired" could not be told from "wired by somebody else".
 */
class RoutesOffTestCase extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        VerifyEmail::$createUrlCallback = null;
        ResetPassword::$createUrlCallback = null;

        $app['config']->set('lukk.routes', false);
    }
}
