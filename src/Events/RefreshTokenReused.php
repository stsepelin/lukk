<?php

declare(strict_types=1);

namespace Lukk\Events;

/**
 * Dispatched when a refresh token that should no longer be usable is presented
 * and its whole family is force-revoked. A security signal — attach a listener
 * to log/alert. `$reason` is 'reuse' (a consumed token replayed past the grace
 * window — the textbook theft signal) or 'revoked' (an already-killed token
 * replayed).
 */
class RefreshTokenReused
{
    public function __construct(
        public readonly string $familyId,
        public readonly string $reason,
    ) {}
}
