<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Database\Eloquent\Relations\HasMany;

/** A Snowflake-keyed user with a SELF-relation (`referrals`), for lookups that join the users' own table. */
class ReferringUser extends SnowflakeUser
{
    protected $table = 'referring_users';

    /**
     * Without the `referrals` scope a subclass adds, which would otherwise apply to the relation's own query
     * and recurse.
     *
     * @return HasMany<static, $this>
     */
    public function referrals(): HasMany
    {
        return $this->hasMany(static::class, 'referrer_id')->withoutGlobalScope('referrals');
    }
}
