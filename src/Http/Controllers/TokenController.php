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
        return (string) ($request->input('refresh_token') ?? $request->cookie(RefreshCookie::name()) ?? '');
    }
}
