<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Lukk\Support\Identifier;

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
            // And nothing sign-in refuses (`Identifier`) — on PostgreSQL a NUL truncates the broker's lookup
            // to a prefix, which is not the address that was submitted. Not left to `email`, whose
            // verdict depends on the validator mode the app configures.
            'email' => ['required', 'string', 'email', 'max:255', Identifier::rule()],
        ];
    }
}
