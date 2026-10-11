<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Lukk\Models\RefreshToken;

/**
 * A refresh-token model pinned to a SECOND connection, so a test can model one application serving
 * two schemas — a migrated tenant and one that has not run the 0.8 `amr` migration.
 */
class TenantBRefreshToken extends RefreshToken
{
    protected $connection = 'tenant_b';

    protected $table = 'refresh_tokens';
}
