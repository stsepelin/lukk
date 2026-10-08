<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lukk\Actions\StartPasskeyConfirmation;
use Lukk\Http\Concerns\PreventsCaching;
use Lukk\Http\Controllers\Concerns\ResolvesAuthenticatedUser;

/** Negotiates the WebAuthn request options for a passkey STEP-UP. See `StartPasskeyConfirmation`. */
class ConfirmablePasskeyOptionsController
{
    use PreventsCaching;
    use ResolvesAuthenticatedUser;

    public function __invoke(Request $request, StartPasskeyConfirmation $start): JsonResponse
    {
        return $this->noStore(response()->json($start($this->authenticated($request))));
    }
}
