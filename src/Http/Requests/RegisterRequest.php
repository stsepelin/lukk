<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Validator as ValidatorFacade;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\Validator;
use Lukk\Lukk;
use Lukk\Support\HashablePassword;
use Lukk\Support\Identifier;
use Lukk\Support\NormalizedPasswordPolicy;

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
    /** Whether the rules in force are lukk's own — which already judge the password as it is stored. */
    private bool $defaultRules = false;

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
        $this->defaultRules = true;

        return [
            // Valid UTF-8 (a `u` pattern matches nothing else): PostgreSQL refuses an invalid sequence
            // in a query parameter (SQLSTATE 22021), so `\xFF` here was a 500 on the INSERT.
            // And no NUL: pdo_pgsql ends a bound string there, so the row held a different name than the
            // one validated.
            'name' => ['required', 'string', 'max:255', 'regex:/^/u', 'not_regex:/\x00/'],
            // max:255 here too — `email`/`unique` on an unbounded string is real work on an
            // unauthenticated endpoint, and every realistic identifier fits (ASVS V2.1).
            // A non-email identifier must be valid UTF-8 as well, for the same reason: `unique` queries
            // with the value. Laravel skips `unique` once an earlier rule on the attribute has failed, so
            // refusing it first is enough — and `email` already refuses such an address.
            // Nothing sign-in refuses (`Identifier`): an account registered with it could never sign in, and on
            // PostgreSQL a NUL stored a truncated identifier that `unique` had never checked.
            $field => $field === 'email'
                ? ['required', 'string', 'max:255', 'email', Identifier::rule(), Rule::unique($this->userModel(), 'email')]
                : ['required', 'string', 'max:255', 'regex:/^/u', Identifier::rule(), Rule::unique($this->userModel(), $field)],
            // max:255 bounds verifier input on this unauthenticated endpoint (ASVS V2.1).
            // The type and NUL-byte checks are `after()`'s, which runs for every rule set, this one included.
            'password' => ['required', 'confirmed', 'max:255', HashablePassword::rule(), new NormalizedPasswordPolicy],
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

                // lukk's own rules have judged the stored spelling already (`NormalizedPasswordPolicy`): asked
                // again they would only run the policy twice — two breach-list lookups, with `uncompromised()`.
                if (! $this->defaultRules) {
                    $this->judgeAsStored($validator, $password);
                }
            }
        }];
    }

    /**
     * Ask the rule set in force about the password AS IT WILL BE STORED, where that is not as typed.
     *
     * lukk's create hashes the NFKC spelling (`HashablePassword::normalize()`), and normalization can
     * shorten a password: four `e` each followed by a combining accent are eight characters as typed and
     * four once composed. The default rules judge the stored spelling themselves
     * (`NormalizedPasswordPolicy`), but a set from `registerValidation()` — or a rebound subclass's — is
     * the application's own, and its `min:12` or `Password::min(12)->mixedCase()` was answered about the
     * typed one. NIST SP 800-63B-4 §3.1.1.2 sets the minimum on the secret the verifier keeps.
     *
     * So the set's own rules for `password` are run once more, on the stored spelling, and whatever they
     * say is said in their words. Nothing else is asked again, and the input is left as it was typed: a
     * rule on another field, the validated data and `registerUsing()` all see what was sent. Only while
     * lukk's own create runs — a `registerUsing()` hook stores what it likes, as typed if it likes.
     */
    private function judgeAsStored(Validator $validator, string $password): void
    {
        $stored = HashablePassword::normalize($password);

        // The ordinary case: nothing to normalize, so the answer already given stands.
        if ($stored === $password) {
            return;
        }

        // Every field that repeats the password is respelled with it — the confirmation, under whatever
        // name the set compares it by (`confirmed`, `same:password_again`, `same:confirm.password`): each
        // has already passed on what was typed, and left as typed it would now differ from the spelling
        // it is compared with. At any depth, since a rule may name a nested field.
        $data = $this->all();
        array_walk_recursive($data, function (mixed &$value) use ($password, $stored): void {
            if ($value === $password) {
                $value = $stored;
            }
        });
        // Only the set's rules for `password`, and none at all where it has none.
        $again = ValidatorFacade::make($data, Arr::only($validator->getRules(), ['password']), $this->messages(), $this->attributes());

        foreach ($again->errors()->all() as $message) {
            $validator->errors()->add('password', $message);
        }
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
