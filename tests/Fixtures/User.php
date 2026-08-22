<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\Factory;
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
    /** @use HasFactory<Factory<static>> */
    use HasFactory;

    use HasRefreshTokens;
    use HasTokenAbilities;
    use HasTwoFactorAuthentication;
    use Notifiable;

    protected $table = 'users';

    protected $guarded = [];

    /**
     * Without these the `@property ?Carbon` declarations above are a LIE — Eloquent hands back a
     * raw string and the analyser would happily accept `->addDays()` on it. A real application's
     * User model casts these; the fixture should behave the same.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'two_factor_confirmed_at' => 'datetime',
    ];

    protected $hidden = ['password'];

    public $timestamps = false;

    protected static function newFactory(): UserFactory
    {
        return UserFactory::new();
    }
}
