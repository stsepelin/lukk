<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Lukk\Concerns\HasRefreshTokens;
use Lukk\Concerns\HasTwoFactorAuthentication;

/**
 * Minimal Eloquent user for guard/login tests. Carries HasRefreshTokens so the
 * trait's ergonomic helpers (startSession, revokeAllSessions) are exercised too.
 */
class User extends Authenticatable
{
    use HasFactory;
    use HasRefreshTokens;
    use HasTwoFactorAuthentication;

    protected $table = 'users';

    protected $guarded = [];

    protected $hidden = ['password'];

    public $timestamps = false;

    protected static function newFactory(): UserFactory
    {
        return UserFactory::new();
    }
}
