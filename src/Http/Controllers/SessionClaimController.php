<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\Response;

/**
 * `POST {prefix}/session/claim` — a deliberate no-op a client calls right after signing in.
 *
 * The claim itself happens in the guard, which marks the session used as it authenticates this
 * request (`claim_seconds`). The route exists so a client can do that immediately, without depending
 * on some application endpoint to be its first request. A bare 204: a fixed acknowledgement, not a swap
 * seam, so there is no Response contract. Mounted whether or not the feature is on, so a client can
 * call it unconditionally.
 */
class SessionClaimController
{
    public function __invoke(): Response
    {
        return response()->noContent();
    }
}
