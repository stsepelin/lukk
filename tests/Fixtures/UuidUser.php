<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Foundation\Auth\User as Authenticatable;

/** A user keyed by Laravel's `HasUuids`: the key is a UUID by the model's own declaration. */
class UuidUser extends Authenticatable
{
    use HasUuids;

    protected $table = 'uuid_users';

    protected $guarded = [];

    public $timestamps = false;
}
