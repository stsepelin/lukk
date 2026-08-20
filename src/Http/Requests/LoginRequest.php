<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

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
            (string) config('lukk.username', 'email') => ['sometimes', 'string', 'max:255'],
            // max:255 bounds verifier input on this unauthenticated endpoint (ASVS V2.1);
            // the length check is identifier-independent, so it leaks no account existence.
            'password' => ['sometimes', 'string', 'max:255'],
        ];
    }
}
