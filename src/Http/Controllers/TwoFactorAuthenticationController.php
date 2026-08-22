<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Lukk\Actions\DisableTwoFactor;
use Lukk\Actions\EnableTwoFactor;
use Lukk\Http\Concerns\PreventsCaching;
use Lukk\Http\Controllers\Concerns\ResolvesAuthenticatedUser;

/**
 * Two-factor enrolment: `store` begins enrolment (returns the secret + otpauth
 * URI to confirm), `destroy` disables it. Both sit behind step-up confirmation.
 */
class TwoFactorAuthenticationController
{
    use PreventsCaching;
    use ResolvesAuthenticatedUser;

    public function __construct(
        private readonly EnableTwoFactor $enable,
        private readonly DisableTwoFactor $disable,
    ) {}

    public function store(Request $request): JsonResponse
    {
        return $this->noStore(response()->json(($this->enable)($this->authenticated($request))));
    }

    public function destroy(Request $request): Response
    {
        ($this->disable)($this->authenticated($request));

        return response()->noContent();
    }
}
