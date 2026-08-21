<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rules\Password;

class ResetPasswordRequest extends FormRequest
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
            // Bounded like login and registration (ASVS V2.1). Without a cap, a reset could set a
            // password LONGER than `/auth/login` will accept — locking the user out of the account
            // they just recovered, with a validation error that explains nothing. The broker token
            // is a fixed 60 chars, and bcrypt truncates at 72 bytes, so neither needs to be huge.
            'token' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255'],
            'password' => ['required', 'confirmed', 'max:255', Password::defaults()],
        ];
    }
}
