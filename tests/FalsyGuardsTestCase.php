<?php

declare(strict_types=1);

namespace Lukk\Tests;

/**
 * `lukk.guards` set to `false` before boot: "no extra guards", the way a `.env`-driven config
 * can leave it. Set pre-boot because the per-guard limiters and routes register in boot().
 */
class FalsyGuardsTestCase extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('lukk.guards', false);
    }
}
