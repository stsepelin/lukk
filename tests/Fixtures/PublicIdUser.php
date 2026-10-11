<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * An auto-incrementing integer primary key that is NOT the auth identifier: the session subject is a
 * public UUID column (`getAuthIdentifierName()`), which is what `EloquentUserProvider::retrieveById()`
 * looks up and what lukk mints `sub` from.
 */
class PublicIdUser extends Authenticatable
{
    protected $table = 'public_id_users';

    protected $guarded = [];

    public $timestamps = false;

    public function getAuthIdentifierName(): string
    {
        return 'public_id';
    }
}
