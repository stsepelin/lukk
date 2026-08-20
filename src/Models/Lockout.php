<?php

declare(strict_types=1);

namespace Lukk\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A consecutive-failure counter for one authenticator on one account.
 *
 * "Consecutive" is the whole point (NIST SP 800-63B §5.2.2): the counter is cleared by any
 * successful authentication and is never decayed by time, so it counts a genuine run of failures
 * rather than a rate. That's also why it lives in the database — a cache entry expires, and a cache
 * flush would silently release every lock.
 *
 * @property string $purpose
 * @property string $subject
 * @property string|null $guard
 * @property int $attempts
 * @property Carbon|null $locked_at
 */
class Lockout extends Model
{
    use HasUlids;

    protected $table = 'lukk_lockouts';

    protected $guarded = [];

    protected function casts(): array
    {
        return ['attempts' => 'integer', 'locked_at' => 'datetime'];
    }
}
