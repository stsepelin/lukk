<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;

/** The stock `increments('id')` shape: a 32-bit integer key, narrower than PHP's int. */
class IntKeyUser extends Authenticatable
{
    protected $table = 'int_key_users';

    protected $guarded = [];

    public $timestamps = false;
}
