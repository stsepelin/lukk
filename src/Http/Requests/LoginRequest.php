<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Lukk\Lukk;

/**
 * Password login input. Type-only (`sometimes`, not `required`) so a custom
 * `Lukk::authenticateUsing` field still works and the unknown-user constant-time
 * path is preserved for a genuinely absent credential — while a malformed type
 * (e.g. `email[]=x`) is rejected with a 422 instead of degrading to a 500. The
 * identifier field name follows `lukk.username` (default `email`).
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
            Lukk::usernameField() => [
                // `sometimes` only states the intent: Laravel skips a non-implicit rule for an absent
                // field anyway, so a missing identifier is refused as a credential, not as a 422.
                'sometimes', // @pest-mutate-ignore: RemoveArrayItem
                'string', 'max:255',
                // Valid UTF-8 (a `u` pattern fails to match anything else). A form body can carry any
                // bytes, and PostgreSQL refuses an invalid sequence in a query parameter (SQLSTATE
                // 22021) — so an `\xFF` in the identifier was a 500 on the lookup instead of a 422.
                'regex:/^/u',
            ],
            // max:255 bounds verifier input on this unauthenticated endpoint (ASVS V2.1);
            // the length check is identifier-independent, so it leaks no account existence.
            'password' => [
                'sometimes', // @pest-mutate-ignore: RemoveArrayItem
                'string', 'max:255',
                // A NUL byte makes `password_hash` throw `ValueError` where `password_verify` only
                // returns false — so the constant-time equalizer, which hashes, raised a 500 on the
                // no-usable-password branches while a real account still got its 422. One crafted
                // request per address, no statistics needed: a stronger oracle than the timing one
                // the equalizer exists to close. `ChangePasswordRequest` carries this rule already.
                'not_regex:/\0/',
                // NOT required to be valid UTF-8, unlike the identifier: the password never reaches SQL,
                // and registration, reset and change-password accept any bytes — a legacy ISO-8859-1
                // form client, or a password set before 0.7. Refusing them here locked such an account
                // out for good, and a reset to the same password looped.
            ],
        ];
    }
}
