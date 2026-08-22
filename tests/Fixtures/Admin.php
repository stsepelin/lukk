<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Lukk\Concerns\HasRefreshTokens;
use Lukk\Concerns\HasTokenAbilities;
use Lukk\Contracts\HasTokenAbilities as HasTokenAbilitiesContract;

/**
 * A second authenticatable behind the `admin` guard — a distinct table from User, so ids collide
 * (admins.id == users.id) and the isolation tests can prove tokens/families don't cross guards.
 */
class Admin extends Authenticatable implements HasTokenAbilitiesContract
{
    use HasFactory;
    use HasRefreshTokens;
    use HasTokenAbilities;

    protected $table = 'admins';

    protected $guarded = [];

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
