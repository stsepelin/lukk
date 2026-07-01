<?php

declare(strict_types=1);

namespace Lukk\Http\Responses;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;
use Lukk\Contracts\EmailVerificationResponse as EmailVerificationResponseContract;

class EmailVerificationResponse implements EmailVerificationResponseContract
{
    public function toResponse($request): Response|RedirectResponse
    {
        $target = (string) config('lukk.email_verification.frontend_url', '');

        // A JSON/SPA client (Accept: application/json), or no frontend URL configured → 204.
        // A plain browser click → bounce to the SPA verify page so the user leaves the raw API
        // (this route is deliberately outside the JSON-forcing group, so `wantsJson` is honest).
        if ($request->wantsJson() || $target === '') {
            return response()->noContent();
        }

        return redirect()->away($target.(str_contains($target, '?') ? '&' : '?').'verified=1');
    }
}
