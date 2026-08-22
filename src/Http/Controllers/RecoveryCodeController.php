<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lukk\Actions\RegenerateRecoveryCodes;
use Lukk\Contracts\TwoFactorAuthenticatable;
use Lukk\Http\Concerns\PreventsCaching;
use Lukk\Http\Controllers\Concerns\ResolvesAuthenticatedUser;

/**
 * Two-factor recovery codes: `index` reports how many remain (a safe count —
 * the codes are hashed and never re-displayable), `store` regenerates the set
 * (invalidating the old codes) and returns the new plaintext once.
 */
class RecoveryCodeController
{
    use PreventsCaching;
    use ResolvesAuthenticatedUser;

    public function __construct(
        private readonly RegenerateRecoveryCodes $regenerate,
    ) {}

    public function index(Request $request): JsonResponse
    {
        /** @var TwoFactorAuthenticatable $user */
        $user = $this->authenticated($request);

        return $this->noStore(response()->json([
            'remaining' => $user->recoveryCodesRemaining(),
            'total' => (int) config('lukk.two_factor.recovery_codes', 8),
        ]));
    }

    public function store(Request $request): JsonResponse
    {
        return $this->noStore(response()->json(['recovery_codes' => ($this->regenerate)($this->authenticated($request))]));
    }
}
