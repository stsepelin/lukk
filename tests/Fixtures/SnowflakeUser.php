<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;

/** An application-generated 64-bit key (Snowflake): `$incrementing` off, `$keyType` left at `'int'` — an integer column lukk is not told about. */
class SnowflakeUser extends Authenticatable
{
    protected $table = 'snowflake_users';

    protected $guarded = [];

    public $timestamps = false;

    public $incrementing = false;
}
