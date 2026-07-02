<?php

declare(strict_types=1);

namespace Lukk\Support;

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
        return (bool) config('lukk.cookie.secure', true);
    }

    public static function name(): string
    {
        $name = (string) config('lukk.cookie.refresh_name', '__Host-refresh');

        return self::secure() ? $name : (string) preg_replace('/^__(Host|Secure)-/', '', $name);
    }
}
