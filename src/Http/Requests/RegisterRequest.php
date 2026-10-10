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
            // Valid UTF-8 (a `u` pattern matches nothing else): PostgreSQL refuses an invalid sequence
            // in a query parameter (SQLSTATE 22021), so `\xFF` here was a 500 on the INSERT.
            'name' => ['required', 'string', 'max:255', 'regex:/^/u'],
            // max:255 here too — `email`/`unique` on an unbounded string is real work on an
            // unauthenticated endpoint, and every realistic identifier fits (ASVS V2.1).
            // A non-email identifier must be valid UTF-8 as well, for the same reason: `unique` queries
            // with the value. Laravel skips `unique` once an earlier rule on the attribute has failed, so
            // refusing it first is enough — and `email` already refuses such an address.
            $field => $field === 'email'
                ? ['required', 'string', 'max:255', 'email', Rule::unique($this->userModel(), 'email')]
                : ['required', 'string', 'max:255', 'regex:/^/u', Rule::unique($this->userModel(), $field)],
            // max:255 bounds verifier input on this unauthenticated endpoint (ASVS V2.1).
            // The type and NUL-byte checks are `after()`'s, which runs for every rule set, this one included.
            'password' => ['required', 'confirmed', 'max:255', HashablePassword::rule(), Password::defaults()],
        ];
    }

    /**
     * What lukk's own create needs of the password, whatever rule set is in force.
     *
     * `registerValidation()` replaces the rules wholesale, as a rebound subclass overriding `rules()`
     * does, and a consumer's set naturally omits a hashing detail: under bcrypt an over-72-byte password
     * was then stored truncated (NIST SP 800-63B-4 §3.1.1.2), and an array or a NUL byte 500'd in the
     * default create. Run for every rule set, the default one included, which leaves the type and
     * NUL-byte checks to it; the 72-byte rule only while lukk's own create runs (the default rules carry
     * that one themselves). And only for a password that is
     * present, so a set that does not require one still decides that itself.
     *
     * @return array<int, \Closure>
     */
    public function after(): array
    {
        // For EVERY rule set, not only `registerValidation()`'s: a rebound subclass overriding `rules()` is
        // the other documented customisation, and it skipped all three checks.
        return [function (Validator $validator): void {
            $password = $this->input('password');

            if ($password === null || $validator->errors()->has('password')) {
                return;
            }

            if (! is_string($password)) {
                $validator->errors()->add('password', __('validation.string', ['attribute' => 'password']));

                return;
            }

            // `Hash::make` throws on a NUL byte — a 500 on a public route.
            if (str_contains($password, "\0")) {
                $validator->errors()->add('password', __('validation.not_regex', ['attribute' => 'password']));

                return;
            }

            // bcrypt's own limit, so only for lukk's create: a `registerUsing()` hook may hand the
            // password to an IdP that takes longer passphrases. The two checks above stand for it too —
            // any hook that hashes would 500 on either.
            if (Lukk::$registerUsing === null) {
                (HashablePassword::rule())('password', $password, fn (string $message) => $validator->errors()->add('password', str_replace(':attribute', 'password', $message)));
            }
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
