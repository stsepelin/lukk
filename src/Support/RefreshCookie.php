<?php

declare(strict_types=1);

namespace Lukk\Support;

use Lukk\Lukk;

/**
 * The refresh-token cookie's name + Secure attribute, resolved together so the set
 * (EmitsTokens), clear (LogoutResponse), and read (TokenController) sites can't drift.
 *
 * Secure defaults on and must stay on in production. When it's off (local dev over
 * plain http, where a browser drops a Secure cookie even on localhost) the `__Host-`/
 * `__Secure-` prefix is stripped from the name — those prefixes require the Secure
 * attribute, so the browser would otherwise reject the cookie outright.
 */
class RefreshCookie
{
    public static function secure(): bool
    {
        return (bool) (Lukk::guardConfig()['cookie']['secure'] ?? true);
    }

    /**
     * The cookie name for the CURRENT guard.
     *
     * Every guard used to set the same `__Host-refresh` at `Path=/`. Guards are allowed to share a
     * host and differ only by path (`assertGuardsIsolated` permits it), so under `cookie_mode`
     * logging into `admin` overwrote the users cookie and vice versa — each login silently
     * destroying the other session. No privilege crossing (the repository is guard-scoped, so a
     * foreign cookie resolves to `unknown` and 401s), but a browser cannot hold both at once.
     *
     * The default guard keeps the unsuffixed name, so a single-guard app is untouched.
     */
    public static function name(): string
    {
        $cfg = Lukk::guardConfig();
        $name = (string) ($cfg['cookie']['refresh_name'] ?? '__Host-refresh');
        $guard = Lukk::currentGuard();

        if ($guard !== (string) config('lukk.guard', 'api')) {
            $name .= '-'.$guard;
        }

        return self::secure() ? $name : (string) preg_replace('/^__(Host|Secure)-/', '', $name);
    }

    /** The refresh TTL in minutes for the CURRENT guard — a per-guard `refresh_ttl` was ignored. */
    public static function ttlMinutes(): int
    {
        return (int) ((int) (Lukk::guardConfig()['refresh_ttl'] ?? 2592000) / 60);
    }
}
