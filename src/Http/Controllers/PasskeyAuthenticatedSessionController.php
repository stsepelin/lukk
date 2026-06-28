<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\Request;
use Lukk\Actions\FinishPasskeyLogin;
use Lukk\Actions\StartSession;
use Lukk\Contracts\LoginResponse;

/**
 * Completes a passwordless passkey login: `store` verifies the assertion against
 * the negotiated ceremony and issues a token pair (`amr: ["webauthn"]`).
 */
class PasskeyAuthenticatedSessionController
{
    public function __construct(
        private readonly FinishPasskeyLogin $finishLogin,
        private readonly StartSession $start,
    ) {}

    public function store(Request $request): LoginResponse
    {
        $request->validate(['ceremony_id' => ['required', 'string'], 'credential' => ['required', 'array']]);

        $userId = ($this->finishLogin)((string) $request->input('ceremony_id'), $request->array('credential'));

        return app(LoginResponse::class, ['pair' => ($this->start)($userId, ['amr' => ['webauthn']])]);
    }
}
