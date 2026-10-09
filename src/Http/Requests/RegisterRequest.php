<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\Validator;
use Lukk\Lukk;
use Lukk\Support\HashablePassword;

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
            // The hook is typed to return an array; the cast only states it.
            return (array) (Lukk::$registerValidation)($this); // @pest-mutate-ignore: RemoveArrayCast
        }

        $field = Lukk::usernameField();

        return [
            'name' => ['required', 'string', 'max:255'],
            // max:255 here too — `email`/`unique` on an unbounded string is real work on an
            // unauthenticated endpoint, and every realistic identifier fits (ASVS V2.1).
            $field => $field === 'email'
                ? ['required', 'string', 'max:255', 'email', Rule::unique($this->userModel(), 'email')]
                : ['required', 'string', 'max:255', Rule::unique($this->userModel(), $field)],
            // max:255 bounds verifier input on this unauthenticated endpoint (ASVS V2.1).
            'password' => ['required', 'confirmed', 'max:255', // A NUL byte makes `Hash::make` throw ("Bcrypt hashing not supported"), which surfaces as a 500
                // on a public endpoint rather than a 422. Nothing else in the rule set rejects one.
                'not_regex:/\0/', HashablePassword::rule(), Password::defaults()],
        ];
    }

    /**
     * What lukk's own create needs of the password, whatever rule set is in force.
     *
     * `registerValidation()` replaces the rules wholesale, and a consumer's set naturally omits a
     * hashing detail: under bcrypt an over-72-byte password was then stored truncated (NIST
     * SP 800-63B-4 §3.1.1.2), and an array one 500'd in the default create. Only with the hook set —
     * the default rules already say both — and only for a password that is present, so a set that
     * does not require one still decides that itself.
     *
     * @return array<int, \Closure>
     */
    public function after(): array
    {
        if (Lukk::$registerValidation === null) {
            return [];
        }

        return [function (Validator $validator): void {
            $password = $this->input('password');

            if ($password === null || $validator->errors()->has('password')) {
                return;
            }

            if (! is_string($password)) {
                $validator->errors()->add('password', __('validation.string', ['attribute' => 'password']));

                return;
            }

            (HashablePassword::rule())('password', $password, fn (string $message) => $validator->errors()->add('password', $message));
        }];
    }

    /**
     * The configured user model, so the unique rule targets the right table.
     *
     * @return class-string
     */
    private function userModel(): string
    {
        $provider = (string) (config('lukk.user_provider') ?? 'users'); // @pest-mutate-ignore: RemoveStringCast

        // Both casts only state types: a provider name only reaches this key, and a missing model
        // fails the unique rule either way.
        /** @var class-string $model */
        $model = (string) config("auth.providers.{$provider}.model"); // @pest-mutate-ignore: RemoveStringCast

        return $model;
    }
}
