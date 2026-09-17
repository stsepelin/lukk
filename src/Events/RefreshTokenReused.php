<?php

declare(strict_types=1);

namespace Lukk\Events;

/**
 * Dispatched when a consumed refresh token is presented past the grace window —
 * the textbook theft signal — and its whole family is force-revoked. Fired from
 * `/refresh` and, with the same decision order, from `/logout`. A security signal —
 * attach a listener to log/alert. `$reason` is 'reuse'; an already-revoked token
 * replayed after a logout is ordinary and no longer fires it (since 0.5.0).
 */
class RefreshTokenReused
{
    public function __construct(
        public readonly string $familyId,
        public readonly string $reason,
    ) {}
}
