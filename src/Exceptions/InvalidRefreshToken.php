<?php

declare(strict_types=1);

namespace Lukk\Exceptions;

use Illuminate\Http\JsonResponse;
use RuntimeException;

/**
 * Thrown by Actions\RotateRefreshToken when a refresh token cannot be exchanged.
 * `$reason` (unknown|revoked|expired|reuse) is for logging only, never leaked to the
 * client; self-renders a 401 so it stays a clean response in any app.
 */
class InvalidRefreshToken extends RuntimeException
{
    public function __construct(public readonly string $reason)
    {
        parent::__construct("Invalid refresh token: {$reason}");
    }

    public function render(): JsonResponse
    {
        return new JsonResponse(['message' => __('The refresh token is invalid or has expired.')], 401);
    }
}
