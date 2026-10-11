<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers\Concerns;

use Illuminate\Http\Request;
use Lukk\Support\FormProofRequest;
use Lukk\Support\RefreshCookie;

/**
 * The refresh tokens a LOGOUT request may be taken at its word on — and whether the refresh cookie
 * was one of them.
 *
 * Stricter than `ReadsPresentedRefreshToken`, which `/refresh` uses, because logout is a state change
 * an attacker profits from forcing. `SameSite=Strict` does not stop it: a sibling page on the same
 * SITE (evil.example.com → api.example.com) gets the cookie sent on a plain form POST, and even fully
 * cross-site, the clearing `Set-Cookie` on a 204 is stored after a top-level navigation. So the cookie
 * is honoured — and later cleared — only on a request a form cannot produce:
 *
 * (`FormProofRequest`): a JSON body, or `Sec-Fetch-Site: same-origin`/`none`.
 *
 * The body `refresh_token` is read from a JSON body only. An attacker cannot know that token, so this
 * is not a CSRF defence in itself — it keeps a single rule for every credential source.
 *
 * A bearer token needs none of this: a cross-origin page cannot set `Authorization` without a
 * preflight.
 */
trait ReadsLogoutCredentials
{
    /**
     * @return array{tokens: array<int, string>, cookie: bool}
     */
    private function logoutCredentials(Request $request): array
    {
        $json = FormProofRequest::hasJsonBody($request);
        $tokens = [];

        $body = $json ? $request->json('refresh_token') : null;

        if (is_string($body) && $body !== '') {
            $tokens[] = $body;
        }

        $cookie = $request->cookie(RefreshCookie::name());
        $cookieUsable = is_string($cookie) && $cookie !== ''
            && FormProofRequest::check($request);

        if ($cookieUsable) {
            $tokens[] = $cookie;
        }

        // `array_values` cannot change the keys here: there are at most two tokens, and `array_unique` keeps the
        // first of a pair, so no gap is ever left. It states the list shape the return type promises.
        return ['tokens' => array_values(array_unique($tokens)), 'cookie' => $cookieUsable]; // @pest-mutate-ignore: UnwrapArrayValues
    }
}
