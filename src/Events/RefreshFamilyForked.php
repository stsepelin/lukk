<?php

declare(strict_types=1);

namespace Lukk\Events;

/**
 * A refresh-token family is carrying more live, unrotated tokens than normal concurrency explains.
 *
 * The grace window deliberately tolerates a re-consumption within `grace_seconds` by minting a
 * fresh sibling instead of revoking the family — that is what keeps a multi-tab or SSR client from
 * logging itself out, and it is not up for negotiation. The cost is that a thief who replays inside
 * that window also gets a sibling, and from then on both chains rotate independently, never
 * colliding and never tripping reuse detection, until `refresh_ttl` expires them.
 *
 * Nothing else in lukk can see that. This is the signal: legitimate concurrency settles at two or
 * three siblings, while a forked family keeps growing. It is deliberately advisory — acting on it
 * would mean revoking on suspicion, which is exactly the false logout the grace window exists to
 * prevent — so listen, alert, and decide for yourself.
 */
class RefreshFamilyForked
{
    public function __construct(
        public readonly int|string $userId,
        public readonly string $familyId,
        /** Live, unrotated tokens in the family at the moment the sibling was minted. */
        public readonly int $liveTokens,
    ) {}
}
