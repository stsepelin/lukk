<?php

declare(strict_types=1);

namespace Lukk\Events;

/**
 * Dispatched when lukk revokes a session because its first use came after `claim_seconds`.
 *
 * Deliberately NOT `RefreshTokenReused`. That event is documented as a theft signal, and apps alert
 * on it; a sign-in response that never reached its client and was used late (or never) is usually a
 * dropped connection. Folding the two together would bury the one alarm that matters under ordinary
 * network noise. Listen to this one to measure lost sign-ins — or, if your clients always claim
 * immediately, to spot a sign-in response being replayed late by someone else.
 */
class SessionUnclaimed
{
    public function __construct(
        public readonly string $familyId,
        public readonly string $guard,
    ) {}
}
