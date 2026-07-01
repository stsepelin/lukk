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
            'code' => ['nullable', 'string'],
            'recovery_code' => ['nullable', 'string'],
        ];
    }
}
