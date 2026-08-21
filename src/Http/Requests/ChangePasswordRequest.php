<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rules\Password;

class ChangePasswordRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public function rules(): array
    {
        return [
            // Bounded at 255 like login, registration and reset — a password the login route would
            // then refuse locks the user out of the account they just secured (ASVS V2.1).
            'current_password' => ['required', 'string', 'max:255'],
            // `confirmed` wants `password_confirmation`. `different` because silently accepting a
            // no-op would report success for a change that didn't happen — and this endpoint
            // revokes every other session, which is a lot of collateral for a no-op.
            'password' => ['required', 'confirmed', 'different:current_password', 'max:255', Password::defaults()],
        ];
    }
}
