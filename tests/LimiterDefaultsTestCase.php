<?php

declare(strict_types=1);

namespace Lukk\Tests;

/**
 * No `rate_limits` block at all — a config cached before it existed — so every limiter falls back to its
 * own default. Set before boot, like the per-guard limiters that read it.
 */
class LimiterDefaultsTestCase extends MultiGuardTestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $lukk = (array) $app['config']->get('lukk');
        unset($lukk['rate_limits']);
        // And the admin guard's own block set to something that is not a block at all.
        $lukk['guards']['admin']['rate_limits'] = 'garbage';
        $app['config']->set('lukk', $lukk);
    }
}
