<?php

declare(strict_types=1);

namespace Lukk\Http\Concerns;

use Illuminate\Http\JsonResponse;

/**
 * Marks a response no-store. Used by every endpoint that returns a secret in its
 * body (tokens, recovery codes, otpauth URI, passkey options, challenge tokens).
 */
trait PreventsCaching
{
    private function noStore(JsonResponse $response): JsonResponse
    {
        return $response->withHeaders([
            'Cache-Control' => 'no-store, private',
            'Pragma' => 'no-cache',
        ]);
    }
}
