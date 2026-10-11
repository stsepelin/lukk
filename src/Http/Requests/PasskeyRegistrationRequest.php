<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

/**
 * Registering a new passkey: the serialized credential plus an optional label.
 */
class PasskeyRegistrationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return array<string, array<int, string|int>>
     */
    public function rules(): array
    {
        return [
            'credential' => ['required', 'array'],
            // Valid UTF-8: it is inserted, and PostgreSQL refuses an invalid sequence (SQLSTATE 22021).
            'name' => ['nullable', 'string', 'max:255', 'regex:/^/u'],
        ];
    }
}
