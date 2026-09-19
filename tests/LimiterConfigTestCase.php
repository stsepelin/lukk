<?php

declare(strict_types=1);

namespace Lukk\Tests;

/**
 * The `admin` guard's rate limits set the way `env()` delivers them — as strings — and to values that
 * differ from every default, set before boot because the per-guard limiters read them during boot.
 */
class LimiterConfigTestCase extends MultiGuardTestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('lukk.guards.admin.rate_limits', [
            'login' => ['ip_max_attempts' => '7', 'decay_seconds' => '71'],
            'refresh' => ['max_attempts' => '8', 'decay_seconds' => '81'],
            'two_factor' => ['max_attempts' => '9', 'decay_seconds' => '91'],
            'confirm' => ['max_attempts' => '4', 'decay_seconds' => '41'],
        ]);
    }
}
