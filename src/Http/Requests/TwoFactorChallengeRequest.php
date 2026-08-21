<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

/**
 * Completing a 2FA login: the challenge token plus a TOTP `code` or a
 * `recovery_code`. Typed so a malformed input renders a 422, not a TypeError 500.
 */
class TwoFactorChallengeRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return array<string, array<int, string>>
     */
    public function rules(): array
    {
        return [
            'challenge_token' => ['required', 'string'],
            // Mutually exclusive. Sending both let one request consume a single rate-limiter slot
            // while performing TWO independent verifications, doubling the effective guess rate —
            // and it is meaningless as a request: the caller knows which credential they hold.
            'code' => ['nullable', 'string', 'prohibits:recovery_code'],
            'recovery_code' => ['nullable', 'string', 'prohibits:code'],
        ];
    }
}
