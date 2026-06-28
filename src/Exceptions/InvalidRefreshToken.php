<?php

declare(strict_types=1);

namespace Lukk\Exceptions;

use Illuminate\Http\JsonResponse;
use RuntimeException;

/**
 * Thrown by Actions\RotateRefreshToken when a refresh token cannot be exchanged.
 * `$reason` is one of: unknown, revoked, expired, reuse.
 *
 * Renders to HTTP 401 (re-authenticate) for every reason — self-rendering so it
 * is a clean 401 in any app, not an uncaught 500. The reason is NOT leaked to
 * the client; it is for logging/metrics only ("reuse" is a security signal
 * worth alerting on).
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
