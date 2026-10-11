<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Str;

/** `HasUlids` with its own id format (`usr_<ulid>`): the model, not `Str::isUlid`, says what a valid key is. */
class PrefixedUlidUser extends Authenticatable
{
    use HasUlids;

    protected $table = 'prefixed_ulid_users';

    protected $guarded = [];

    public $timestamps = false;

    public function newUniqueId(): string
    {
        return 'usr_'.strtolower((string) Str::ulid());
    }

    protected function isValidUniqueId($value): bool
    {
        return is_string($value) && str_starts_with($value, 'usr_') && Str::isUlid(substr($value, 4));
    }
}
