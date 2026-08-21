<?php

declare(strict_types=1);

namespace Lukk\Concerns;

use Lukk\Support\Abilities;

/**
 * `$user->tokenCan('orders.read')` — what the CURRENT request's token is allowed to do.
 *
 * Scoped to the token, not to the user: the same person on two devices may hold tokens with
 * different abilities, and that is the point of the feature. The guard populates this from the
 * verified `scope` claim on each request, so it is empty outside an authenticated request rather
 * than silently reporting a previous one's.
 */
trait HasAbilities
{
    protected ?Abilities $tokenAbilities = null;

    /** Called by the guard with the verified token's `scope`. */
    public function withTokenAbilities(Abilities $abilities): static
    {
        $this->tokenAbilities = $abilities;

        return $this;
    }

    public function tokenAbilities(): Abilities
    {
        return $this->tokenAbilities ??= Abilities::fromArray([]);
    }

    public function tokenCan(string $ability): bool
    {
        return $this->tokenAbilities()->can($ability);
    }

    public function tokenCannot(string $ability): bool
    {
        return ! $this->tokenCan($ability);
    }
}
