<?php

declare(strict_types=1);

namespace Lukk\Tests;

/**
 * Boots the app with feature flags forced OFF.
 *
 * Routes are registered during boot, so a `config()` call inside a test is too late to un-register
 * one — the flag has to be set before the provider runs. Set `static::$disable` in the test file.
 */
class DisabledFeatureTestCase extends TestCase
{
    /** @var array<int, string> feature keys to force off, e.g. `['change_password']` */
    public static array $disable = [];

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        foreach (static::$disable as $feature) {
            $app['config']->set("lukk.features.{$feature}", false);
        }
    }
}
