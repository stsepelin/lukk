<?php

declare(strict_types=1);

namespace Lukk\Support;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;

/**
 * `Password::defaults()`, applied to the password AS IT WILL BE HASHED.
 *
 * lukk stores a new password normalized (`HashablePassword::normalize()`, NFKC), and normalization can
 * shorten one: four `e` each followed by a combining accent are eight characters as typed and four once
 * composed. Judged as typed, that password passed an eight-character minimum and was then stored — and
 * signed in with — as four. NIST SP 800-63B-4 §3.1.1.2 sets the minimum on the secret the verifier
 * keeps. So the application's own policy is asked about the normalized spelling, and answers in its own
 * words.
 *
 * A class rather than a closure so that a failure names it (`Validator::failed()`), apart from the
 * 72-byte rule beside it.
 */
class NormalizedPasswordPolicy implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        // Not a string is the `string` rule's to refuse; there is nothing here to normalize.
        if (! is_string($value)) {
            return;
        }

        $judged = Validator::make([$attribute => HashablePassword::normalize($value)], [$attribute => [Password::defaults()]]);

        foreach ($judged->errors()->all() as $message) {
            $fail($message);
        }
    }
}
