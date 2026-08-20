<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class ForgotPasswordRequest extends FormRequest
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
            // Unauthenticated, so bound it: an unbounded address reaches the RFC validator and a DB
            // lookup on every request, and matches the cap login and registration already carry.
            'email' => ['required', 'string', 'email', 'max:255'],
        ];
    }
}
