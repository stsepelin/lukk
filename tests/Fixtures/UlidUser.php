<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Foundation\Auth\User as Authenticatable;

/** A user keyed by Laravel's `HasUlids`: the key is a ULID by the model's own declaration. */
class UlidUser extends Authenticatable
{
    use HasUlids;

    protected $table = 'ulid_users';

    protected $guarded = [];

    public $timestamps = false;
}
