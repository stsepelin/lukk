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
        if ($this->current !== null) {
            return $this->current;
        }

        // No `lukk.set-guard` ran, so this is a consumer's own route — and falling straight back to
        // the default guard was silently wrong there. `app(RevokeAllSessions::class)($admin->id)`
        // on an `auth:admin` route revoked the USERS guard's families for a colliding id: the
        // admin's sessions survived a "revoke everything" call, and an unrelated user's were
        // destroyed. `Authenticate` calls `shouldUse()` for the guard that passed, so the auth
        // manager names the guard that actually authenticated this request.
        //
        // Only honoured for a guard lukk knows: a hybrid app's session `web` guard has no lukk
        // identity, and reading config for it would just be the default guard under another name.
        $resolved = (string) app('auth')->getDefaultDriver();
        $default = (string) config('lukk.guard', 'api');

        return $resolved === $default || isset(((array) config('lukk.guards', []))[$resolved])
            ? $resolved
            : $default;
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
