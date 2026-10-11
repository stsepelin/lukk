<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * A user that eager-loads (`$with`) a relation whose keys disagree in type: `things.owner_uuid` is a UUID,
 * compared with the user's `email`. Every lookup of this user then fails on PostgreSQL with 22P02 — in the
 * RELATION's statement, not the lookup of the subject.
 */
class EagerThingsUser extends User
{
    protected $with = ['things'];

    /** @return HasMany<Thing, $this> */
    public function things(): HasMany
    {
        return $this->hasMany(Thing::class, 'owner_uuid', 'email');
    }
}
