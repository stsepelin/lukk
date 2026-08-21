<?php

declare(strict_types=1);

namespace Lukk\Actions\Concerns;

use Illuminate\Validation\ValidationException;

/**
 * The one place the "this account is locked" response is defined.
 *
 * Four actions reach this state — login, step-up confirmation, the two-factor challenge and a
 * password change — and every one of them owes the same contract: **423**, not 429, because with
 * `release_after` at 0 "try again later" is untrue; a message naming the wait when there is one and
 * pointing at support when there isn't. Only the error-bag field and the lockout purpose differ.
 *
 * Kept together because it is a policy, not a coincidence: four copies of a status code and a
 * translation key are four chances for one of them to drift.
 *
 * Consuming classes supply `$lockouts` and implement `lockoutGuard()` — declared abstract rather
 * than reaching for a `$guard` property, because `AttemptLogin` derives its guard from the rate
 * limiter instead of holding one, and an implicit property requirement would fatal there.
 */
trait ThrowsWhenLocked
{
    abstract private function lockoutGuard(): ?string;

    private function throwLocked(string $purpose, string $subject, string $field): never
    {
        $seconds = $this->lockouts?->availableIn($purpose, $subject, $this->lockoutGuard());

        throw ValidationException::withMessages([
            $field => [$seconds === null
                ? __('This account is locked. Contact support to restore access.')
                : __('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)])],
        ])->status(423);
    }
}
