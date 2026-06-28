<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Lukk\Auth\ChallengeToken;
use Symfony\Component\HttpFoundation\Response;

/**
 * Gate a route behind a recent step-up confirmation ("sudo" mode). The client
 * earns a confirmation token (POST /auth/confirm-password, or a passkey assertion)
 * and presents it in the configured header; the token is valid for the whole
 * `confirm.ttl` window. Returns 423 Locked when missing/expired/foreign.
 */
class RequireConfirmation
{
    public function __construct(private readonly ChallengeToken $challengeTokens) {}

    public function handle(Request $request, Closure $next): Response
    {
        $token = (string) $request->header((string) config('lukk.confirm.header', 'X-Lukk-Confirmation'), '');
        $subject = $this->challengeTokens->verify('reauth', $token);

        abort_if(
            $subject === null || $subject !== (string) $request->user()?->getAuthIdentifier(),
            423,
            'This action requires confirmation.',
        );

        return $next($request);
    }
}
