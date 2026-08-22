<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\Request;
use Lukk\Actions\RotateRefreshToken;
use Lukk\Contracts\RefreshResponse;
use Lukk\Support\RefreshCookie;

/**
 * Mints a fresh token pair from a presented refresh token (rotation + reuse
 * detection live in the Action). Thin — runs the Action, returns the contract.
 */
class TokenController
{
    public function __construct(
        private readonly RotateRefreshToken $rotate,
    ) {}

    public function store(Request $request): RefreshResponse
    {
        $pair = ($this->rotate)($this->presentedRefreshToken($request));

        return app(RefreshResponse::class, ['pair' => $pair]);
    }

    private function presentedRefreshToken(Request $request): string
    {
        // `input()` unions the QUERY STRING for every content type, so `POST /auth/refresh?refresh_token=…`
        // worked — putting a 30-day opaque credential into access logs, proxy logs and Referer
        // headers, the one place a token kept out of caches and hashed at rest must never appear
        // (RFC 9700 §4.3.2). Body only. `post()` covers form encoding, `json()` the JSON body.
        $presented = $request->post('refresh_token') ?? $request->json('refresh_token');

        // An array would raise "Array to string conversion" and hash the literal "Array".
        $cookie = $request->cookie(RefreshCookie::name());

        return is_string($presented) ? $presented : (is_string($cookie) ? $cookie : '');
    }
}
