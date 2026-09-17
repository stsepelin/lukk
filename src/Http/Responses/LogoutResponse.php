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
        if ($this->clearRefreshCookie && (bool) (Lukk::guardConfig()['cookie_mode'] ?? false)) {
            // Delete with the same name + attributes (Secure + Path=/) the cookie was
            // set with, so strict browsers actually honor the removal.
            $response->withCookie(cookie()->make(
                name: RefreshCookie::name(),
                value: '',
                minutes: -2628000,
                path: '/',
                domain: null,
                secure: RefreshCookie::secure(),
                httpOnly: true,
                raw: false,
                sameSite: 'Strict',
            ));
        }

        return $response;
    }
}
