<?php

declare(strict_types=1);

namespace Lukk\Http\Responses;

use Illuminate\Http\Response;
use Lukk\Contracts\LogoutResponse as LogoutResponseContract;
use Lukk\Lukk;
use Lukk\Support\RefreshCookie;

class LogoutResponse implements LogoutResponseContract
{
    /**
     * @param  bool  $clearRefreshCookie  False when `POST /logout` did not accept the refresh cookie from
     *                                    this request (none presented, or a request shape a cross-site
     *                                    form could produce). A rebound implementation should honour it:
     *                                    a clearing `Set-Cookie` on such a request is a forced logout.
     */
    public function __construct(private readonly bool $clearRefreshCookie = true) {}

    public function toResponse($request): Response
    {
        $response = response()->noContent();

        // Per guard, exactly as `EmitsTokens` decides whether to SET the cookie. Read globally, a
        // guard that opted into cookie mode was never sent the clear for the cookie its login set.
        // (The cast only states the type: `&&` reads the value's truthiness either way.)
        if ($this->clearRefreshCookie && (bool) (Lukk::guardConfig()['cookie_mode'] ?? false)) { // @pest-mutate-ignore: RemoveBooleanCast
            // Delete with the same name + attributes (Secure + Path=/) the cookie was
            // set with, so strict browsers actually honor the removal.
            // `->withDomain(null)`: `CookieJar` resolves the domain as `$domain ?: $this->domain` and
            // its default comes from `session.domain`, so under `SESSION_DOMAIN` this clear carried a
            // Domain the set never had — and a `__Host-` cookie with Domain is discarded outright
            // (rfc6265bis §4.1.3.2), leaving the very cookie this exists to remove in place.
            $response->withCookie((cookie()->make(
                name: RefreshCookie::name(),
                value: '',
                // Any past expiry deletes the cookie; five years back is simply unambiguous.
                minutes: -2628000, // @pest-mutate-ignore: DecrementInteger,IncrementInteger
                path: '/',
                domain: null,
                secure: RefreshCookie::secure(),
                httpOnly: true,
                // An empty value and a plain name encode the same raw or not.
                raw: false, // @pest-mutate-ignore: FalseToTrue
                sameSite: 'Strict',
            ))->withDomain(null));
        }

        return $response;
    }
}
