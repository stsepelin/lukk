<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Lukk\Actions\StartPasskeyLogin;
use Lukk\Http\Concerns\PreventsCaching;

/**
 * Negotiates the WebAuthn request options (challenge + opaque ceremony id) for a
 * passwordless passkey login. Public + single-action.
 */
class PasskeyLoginOptionsController
{
    use PreventsCaching;

    public function __construct(
        private readonly StartPasskeyLogin $startLogin,
    ) {}

    public function __invoke(): JsonResponse
    {
        return $this->noStore(response()->json(($this->startLogin)()));
    }
}
