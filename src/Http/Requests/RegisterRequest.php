<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;
use Lukk\Lukk;

/**
 * Registration input. Defaults to the stock Laravel shape: `name`, the unique identifier column
 * (`lukk.username` — an `email` by default, or a `username`), and a confirmed `password` meeting
 * `Password::defaults()`. Customize the fields two ways: rebind this class to a subclass, or set
 * `Lukk::registerValidation()`. Malformed input is a 422, never a 500.
 *
 * The `unique` rule already reveals whether an identifier is registered — that's the accepted,
 * minimal leak of any registration form; lukk adds no faster enumeration oracle beyond it.
 */
class RegisterRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        if (Lukk::$registerValidation !== null) {
            return (array) (Lukk::$registerValidation)($this);
        }

        $field = (string) config('lukk.username', 'email');

        return [
            'name' => ['required', 'string', 'max:255'],
            $field => $field === 'email'
                ? ['required', 'string', 'email', Rule::unique($this->userModel(), 'email')]
                : ['required', 'string', Rule::unique($this->userModel(), $field)],
            // max:255 bounds verifier input on this unauthenticated endpoint (ASVS V2.1).
            'password' => ['required', 'confirmed', 'max:255', Password::defaults()],
        ];
    }

    /**
     * The configured user model, so the unique rule targets the right table.
     *
     * @return class-string
     */
    private function userModel(): string
    {
        $provider = (string) config('lukk.user_provider', 'users');

        return (string) config("auth.providers.{$provider}.model");
    }
}
