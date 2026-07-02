<?php

declare(strict_types=1);

namespace Lukk\Http\Responses;

use Illuminate\Http\Response;
use Lukk\Contracts\LogoutResponse as LogoutResponseContract;
use Lukk\Support\RefreshCookie;

class LogoutResponse implements LogoutResponseContract
{
    public function toResponse($request): Response
    {
        $response = response()->noContent();

        if (config('lukk.cookie_mode')) {
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
