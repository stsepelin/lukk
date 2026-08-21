<?php

declare(strict_types=1);

namespace Lukk\Tests;

/**
 * Boots the app with feature flags forced OFF.
 *
 * Routes are registered during boot, so a `config()` call inside a test is too late to un-register
 * one — the flag has to be set before the provider runs.
 *
 * The list is an overridable METHOD, not a static property. A static would be written at file-load
 * time and read at boot time, and PHPUnit loads every test file before running any test — so a
 * second test file setting it would silently win for the whole run, breaking the first. That is not
 * hypothetical: it was the shape this class shipped in, and it survived only because exactly one
 * file used it. Per-class state is also the idiom the rest of this suite already uses
 * (`MultiGuardTestCase`, `ConcurrencyTestCase`), and it is safe under `pest --parallel`, where a
 * worker reuses its process across classes.
 */
abstract class DisabledFeatureTestCase extends TestCase
{
    /** @return array<int, string> feature keys to force off, e.g. `['change_password']` */
    abstract protected function disabledFeatures(): array;

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        foreach ($this->disabledFeatures() as $feature) {
            $app['config']->set("lukk.features.{$feature}", false);
        }
    }
}
