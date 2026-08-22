<?php

declare(strict_types=1);

namespace Lukk\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * A verified token was refused a route because its `scope` didn't cover it.
 *
 * lukk announces every other security transition it owns — `AccountLocked`, `RefreshTokenReused`,
 * `PasskeyCloneDetected`, `PasswordChanged` — and an authorization refusal belongs in that set: a
 * stolen token probing for what it can reach looks exactly like a run of these, and without the
 * event a deployment has no lukk-side signal at all.
 *
 * An event rather than a log line, deliberately. Ability names travel widely enough already (the
 * claim, the user resource, your JS bundle); writing them into the application log adds a sink
 * nobody asked for, and lets an integrator who wants one opt in.
 */
class TokenAbilityDenied
{
    use Dispatchable;

    /**
     * @param  array<int, string>  $required  What the ROUTE asked for — never what the caller holds.
     *                                        A queued listener serializes this payload, so it stays
     *                                        identifiers plus the requirement; the caller's own
     *                                        grant is not lukk's to spread further.
     */
    public function __construct(
        public readonly int|string $userId,
        public readonly string $guard,
        public readonly string $familyId,
        public readonly array $required,
        /** True for `lukk.abilities` (ALL), false for `lukk.ability` (ANY). */
        public readonly bool $requiresAll,
    ) {}
}
