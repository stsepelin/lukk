<?php

declare(strict_types=1);

namespace Lukk\Concerns;

use Lukk\Support\Abilities;
use Lukk\Support\VerifiedToken;

/**
 * `$user->tokenCan('orders.read')` — what the CURRENT request's token is allowed to do.
 *
 * Scoped to the token, not to the user: the same person on two devices may hold tokens with
 * different abilities, and that is the point of the feature. The answer is read from the request
 * (see {@see VerifiedToken}) rather than from state on this object, so it is correct on a model the
 * guard never resolved and cannot go stale on one that outlives its request.
 *
 * Outside an authenticated request — a queued job, a console command — nothing is granted. Deny by
 * default: an authorization check has no business passing where no token was presented.
 *
 * Named identically to {@see \Lukk\Contracts\HasTokenAbilities}, which it satisfies — Sanctum and
 * the framework both pair a trait and an interface under one name, so a class using both aliases the
 * contract (`use Lukk\Contracts\HasTokenAbilities as HasTokenAbilitiesContract;`). One name for one
 * concept beats two names a reader has to learn separately.
 */
trait HasTokenAbilities
{
    public function tokenAbilities(): Abilities
    {
        return VerifiedToken::forUser(request(), $this)?->abilities ?? Abilities::fromArray([]);
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
