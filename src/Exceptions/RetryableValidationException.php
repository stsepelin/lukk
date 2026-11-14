<?php

declare(strict_types=1);

namespace Lukk\Exceptions;

use Illuminate\Validation\ValidationException;

/**
 * A 429 or 423 that knows when to come back: an ordinary validation error, rendered exactly as the
 * application renders any other, that also carries the wait in seconds.
 *
 * The wait used to live only inside a translated sentence. RFC 9110 §10.2.3 gives it a header, and the
 * route-level throttle on the same endpoints already sends one — so a client honouring `Retry-After`
 * backed off for the 429 the framework threw and hammered the one lukk's own action threw.
 * `ForceJsonRequest`, which wraps every lukk route, reads the wait from here and stamps the header; the
 * exception does not build its own response, because that would bypass an application's
 * `invalidJson()` shape.
 */
class RetryableValidationException extends ValidationException
{
    /** Whole seconds until the same request can succeed. */
    public int $retryAfter = 1;

    /**
     * Never below one second: a `Retry-After: 0` reads as "now", which a refusal that just happened is not.
     */
    public function retryAfter(int $seconds): static
    {
        $this->retryAfter = max(1, $seconds);

        return $this;
    }
}
