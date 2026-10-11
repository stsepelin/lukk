<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Lukk\Models\RefreshToken;

/**
 * A `useRefreshTokenModel` subclass that stamps a required `tenant_id` the way a `BelongsToTenant` trait
 * would — once from a `creating` listener (which lukk's quiet write never fires), once from the trait's
 * `initialize…()` method, which Eloquent runs as every instance is BUILT, with no event dispatched.
 */
class TenantScopedRefreshToken extends RefreshToken
{
    use FillsTenantOnInitialize;

    protected $table = 'refresh_tokens';

    public static ?string $tenant = null;

    protected static function booted(): void
    {
        static::creating(function (self $token) {
            $token->setAttribute('tenant_from_creating', self::$tenant);
        });
    }
}
