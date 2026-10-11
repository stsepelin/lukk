<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;

/** An auto-incrementing key whose auth identifier is ANOTHER integer column (`legacy_id`). */
class LegacyIdUser extends Authenticatable
{
    protected $table = 'legacy_id_users';

    protected $guarded = [];

    public $timestamps = false;

    public function getAuthIdentifierName(): string
    {
        return 'legacy_id';
    }
}
