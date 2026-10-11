<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;

/** A row owned by a user through a UUID column — the related side of `EagerThingsUser`'s mistyped relation. */
class Thing extends Model
{
    protected $table = 'things';

    protected $guarded = [];

    public $timestamps = false;
}
