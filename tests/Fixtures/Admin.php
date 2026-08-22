<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Carbon;
use Lukk\Concerns\HasRefreshTokens;
use Lukk\Concerns\HasTokenAbilities;
use Lukk\Contracts\HasTokenAbilities as HasTokenAbilitiesContract;

/**
 * A second authenticatable behind the `admin` guard — a distinct table from User, so ids collide
 * (admins.id == users.id) and the isolation tests can prove tokens/families don't cross guards.
 *
 * @property int $id
 * @property ?string $name
 * @property string $email
 * @property string $password
 * @property ?Carbon $two_factor_confirmed_at
 * @property ?Carbon $email_verified_at
 */
class Admin extends Authenticatable implements HasTokenAbilitiesContract
{
    /** @use HasFactory<Factory<static>> */
    use HasFactory;

    use HasRefreshTokens;
    use HasTokenAbilities;

    protected $table = 'admins';

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

    /** This model authenticates under the `admin` guard. */
    public function lukkGuard(): string
    {
        return 'admin';
    }

    protected static function newFactory(): AdminFactory
    {
        return AdminFactory::new();
    }
}
