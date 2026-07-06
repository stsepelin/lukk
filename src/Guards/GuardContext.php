<?php

declare(strict_types=1);

namespace Lukk\Guards;

use Closure;

/**
 * Holds the lukk guard active for the current request. Login/refresh/logout run on public or
 * per-guard routes rather than through Laravel's `auth:{guard}` resolution, so the route group's
 * middleware stamps the guard here and the token bindings (issuer/verifier/repository) resolve
 * that guard's config. Unset → the default guard (`config('lukk.guard')`).
 *
 * Bound as a `scoped` binding, so it is per-request in FPM and reset between requests in Octane.
 */
class GuardContext
{
    private ?string $current = null;

    public function current(): string
    {
        return $this->current ?? (string) config('lukk.guard', 'api');
    }

    public function use(?string $name): void
    {
        $this->current = $name;
    }

    /**
     * Run a callback with a given guard active, restoring the previous guard afterwards.
     */
    public function on(string $name, Closure $callback): mixed
    {
        $previous = $this->current;
        $this->current = $name;

        try {
            return $callback();
        } finally {
            $this->current = $previous;
        }
    }
}
