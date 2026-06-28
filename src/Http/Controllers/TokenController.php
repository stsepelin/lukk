<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\Request;
use Lukk\Actions\RotateRefreshToken;
use Lukk\Contracts\RefreshResponse;

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
        $cookieName = (string) config('lukk.cookie.refresh_name', '__Host-refresh');

        return (string) ($request->input('refresh_token') ?? $request->cookie($cookieName) ?? '');
    }
}
