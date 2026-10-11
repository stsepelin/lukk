<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * A string primary key (`usr_…`) on a model that turned `$incrementing` off but never declared
 * `$keyType = 'string'` — Eloquent's default `'int'` is then a leftover, not a statement about the column.
 */
class StringKeyUser extends Authenticatable
{
    protected $table = 'string_key_users';

    public $incrementing = false;

    protected $guarded = [];

    public $timestamps = false;
}
