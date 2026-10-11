<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

/** The documented way to fill a required column on lukk's quiet refresh-token write. */
trait FillsTenantOnInitialize
{
    public function initializeFillsTenantOnInitialize(): void
    {
        $this->setAttribute('tenant_id', TenantScopedRefreshToken::$tenant);
    }
}
