<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class ConfirmPasswordRequest extends FormRequest
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
            // `string` because the controller casts this to one: an array or object there raised
            // "Array to string conversion", which `HandleExceptions` promotes to an ErrorException
            // and renders as a 500 — against this package's own rule that malformed input renders
            // 422. `PasskeyAssertionRequest` documents the identical bug and its identical fix.
            //
            // `max:255` to match `ChangePasswordRequest::current_password`: the same bound login,
            // registration and reset all carry, so an unbounded string cannot buy hashing work on
            // a route whose whole purpose is to verify a password.
            'password' => ['required', 'string', 'max:255'],
        ];
    }
}
