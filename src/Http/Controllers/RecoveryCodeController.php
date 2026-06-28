<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lukk\Actions\RegenerateRecoveryCodes;
use Lukk\Http\Concerns\PreventsCaching;

/**
 * Two-factor recovery codes: `index` reports how many remain (a safe count —
 * the codes are hashed and never re-displayable), `store` regenerates the set
 * (invalidating the old codes) and returns the new plaintext once.
 */
class RecoveryCodeController
{
    use PreventsCaching;

    public function __construct(
        private readonly RegenerateRecoveryCodes $regenerate,
    ) {}

    public function index(Request $request): JsonResponse
    {
        return $this->noStore(response()->json([
            'remaining' => $request->user()->recoveryCodesRemaining(),
            'total' => (int) config('lukk.two_factor.recovery_codes', 8),
        ]));
    }

    public function store(Request $request): JsonResponse
    {
        return $this->noStore(response()->json(['recovery_codes' => ($this->regenerate)($request->user())]));
    }
}
