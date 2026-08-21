<?php

declare(strict_types=1);

namespace Lukk\Tests;

class ChangePasswordDisabledTestCase extends DisabledFeatureTestCase
{
    protected function disabledFeatures(): array
    {
        return ['change_password'];
    }
}
