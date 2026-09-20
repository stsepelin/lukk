<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Lukk\Lukk;

/**
 * Password login input. Type-only (`sometimes`, not `required`) so a custom
 * `Lukk::authenticateUsing` field still works and the unknown-user constant-time
 * path is preserved for a genuinely absent credential — while a malformed type
 * (e.g. `email[]=x`) is rejected with a 422 instead of degrading to a 500. The
 * identifier field name follows `lukk.username` (default `email`).
 */
class LoginRequest extends FormRequest
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
            Lukk::usernameField() => [
                // `sometimes` only states the intent: Laravel skips a non-implicit rule for an absent
                // field anyway, so a missing identifier is refused as a credential, not as a 422.
                'sometimes', // @pest-mutate-ignore: RemoveArrayItem
                'string', 'max:255',
            ],
            // max:255 bounds verifier input on this unauthenticated endpoint (ASVS V2.1);
            // the length check is identifier-independent, so it leaks no account existence.
            'password' => [
                'sometimes', // @pest-mutate-ignore: RemoveArrayItem
                'string', 'max:255',
            ],
        ];
    }
}
