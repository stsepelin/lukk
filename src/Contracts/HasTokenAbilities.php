<?php

declare(strict_types=1);

namespace Lukk\Contracts;

use Lukk\Support\Abilities;

/**
 * A user model that can be asked what the CURRENT request's token may do.
 *
 * Satisfied by the `Lukk\Concerns\HasTokenAbilities` trait, which carries the same name on purpose:
 * Sanctum and the framework both pair a trait and an interface under one name, so a class using both
 * aliases the contract (`use Lukk\Contracts\HasTokenAbilities as HasTokenAbilitiesContract;`). One
 * name for one concept beats two names a reader has to learn separately.
 *
 * Nothing inside lukk type-hints this — the gates read the request's verified token, not the user —
 * so it is deliberately a **consumer-facing marker**: something for your own code to type against
 * (`function (HasTokenAbilities $user)`) instead of `method_exists`, which cannot tell a real
 * implementation from a same-named method that means something else. Sanctum ships its equivalent
 * on the same reasoning.
 */
interface HasTokenAbilities
{
    public function tokenAbilities(): Abilities;

    public function tokenCan(string $ability): bool;

    public function tokenCannot(string $ability): bool;
}
