<?php

declare(strict_types=1);

namespace Lukk\Tests;

class AccountDeletionDisabledTestCase extends DisabledFeatureTestCase
{
    protected function disabledFeatures(): array
    {
        return ['account_deletion'];
    }
}
