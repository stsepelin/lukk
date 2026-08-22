<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Carbon;
use Lukk\Concerns\HasRefreshTokens;
use Lukk\Concerns\HasTokenAbilities;
use Lukk\Concerns\HasTwoFactorAuthentication;
use Lukk\Contracts\HasTokenAbilities as HasTokenAbilitiesContract;

/**
 * Minimal Eloquent user for guard/login tests. Carries HasRefreshTokens so the
 * trait's ergonomic helpers (startSession, revokeAllSessions) are exercised too.
 *
 * @property int $id
 * @property ?string $name
 * @property string $email
 * @property string $password
 * @property ?Carbon $two_factor_confirmed_at
 * @property ?Carbon $email_verified_at
 */
class User extends Authenticatable implements HasTokenAbilitiesContract, MustVerifyEmail
{
    use HasFactory;
    use HasRefreshTokens;
    use HasTokenAbilities;
    use HasTwoFactorAuthentication;
    use Notifiable;

    protected $table = 'users';

    protected $guarded = [];

    protected $hidden = ['password'];

    public $timestamps = false;

    protected static function newFactory(): UserFactory
    {
        return UserFactory::new();
    }
}
