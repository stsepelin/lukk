<?php

declare(strict_types=1);

namespace Lukk\Contracts;

use Lukk\Concerns\HasAbilities;
use Lukk\Support\Abilities;

/**
 * A user model that can be asked what the CURRENT request's token may do.
 *
 * Satisfied by the {@see HasAbilities} trait; declared as a contract so callers get
 * a type to check against instead of `method_exists`, which cannot tell a real implementation from
 * a same-named method that means something else.
 */
interface HasTokenAbilities
{
    public function tokenAbilities(): Abilities;

    public function tokenCan(string $ability): bool;

    public function tokenCannot(string $ability): bool;
}
