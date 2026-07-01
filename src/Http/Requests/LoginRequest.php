<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

/**
 * Password login input. Type-only (`sometimes`, not `required`) so a custom
 * `Lukk::authenticateUsing` field still works and the unknown-user constant-time
 * path is preserved for a genuinely absent credential — while a malformed type
 * (e.g. `email[]=x`) is rejected with a 422 instead of degrading to a 500.
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
            'email' => ['sometimes', 'string'],
            'password' => ['sometimes', 'string'],
        ];
    }
}
