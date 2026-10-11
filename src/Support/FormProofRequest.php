<?php

declare(strict_types=1);

namespace Lukk\Support;

use Illuminate\Http\Request;

/**
 * Whether a request is one a cross-site HTML form cannot produce.
 *
 *  - `Content-Type: application/json`. Not CORS-safelisted, so a cross-origin page must pass a preflight
 *    the application's CORS policy governs. Matched on the MIME ESSENCE: a substring test (`isJson()`)
 *    accepts `text/plain; x=/json`, which is safelisted and needs no preflight.
 *  - `Sec-Fetch-Site: same-origin` or `none` (the user's own navigation). Not `same-site`: that is the
 *    sibling-subdomain attacker — and also where a direct-mode SPA usually lives, which is why such a
 *    client sends JSON rather than relying on this header.
 */
class FormProofRequest
{
    public static function check(Request $request): bool
    {
        return self::hasJsonBody($request)
            || in_array($request->headers->get('Sec-Fetch-Site'), ['same-origin', 'none'], true);
    }

    public static function hasJsonBody(Request $request): bool
    {
        // The cast is load-bearing: under `strict_types` a missing header (null) makes `explode` throw a TypeError,
        // so a body-less request — a BFF's, a `sendBeacon` — would answer 500. The limit is not: element [0] is the
        // same at any limit above 1.
        $essence = explode(';', (string) $request->headers->get('Content-Type'), 2)[0]; // @pest-mutate-ignore: IncrementInteger

        return strtolower(trim($essence)) === 'application/json';
    }
}
