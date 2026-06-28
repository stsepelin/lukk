<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lukk\Actions\StartPasskeyRegistration;
use Lukk\Http\Concerns\PreventsCaching;

/**
 * Negotiates the WebAuthn creation options (challenge, RP, exclude list) for
 * registering a new passkey. Single-action; sits behind step-up confirmation.
 */
class PasskeyRegistrationOptionsController
{
    use PreventsCaching;

    public function __construct(
        private readonly StartPasskeyRegistration $startRegistration,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        return $this->noStore(response()->json(($this->startRegistration)($request->user())));
    }
}
