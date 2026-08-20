<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Validation\ValidationException;
use Lukk\Contracts\LockoutRepository;

/**
 * Re-verify the authenticated user's password for a step-up ("sudo") confirmation.
 *
 * This checks the SAME secret as login, so it needs the same defences: the route is throttled
 * (`lukk-confirm`, per user and per IP), and — when `features.lockout` is on — a run of failures
 * here counts toward the same NIST SP 800-63B §5.2.2 cap. Without both, a caller holding an access
 * token had an unmetered password oracle sitting behind the sudo gate.
 */
class ConfirmPassword
{
    public function __construct(
        private readonly UserProvider $users,
        // Null unless `features.lockout` is on.
        private readonly ?LockoutRepository $lockouts = null,
        private readonly ?string $guard = null,
    ) {}

    public function __invoke(Authenticatable $user, string $password): void
    {
        $subject = (string) $user->getAuthIdentifier();

        // Keyed on the user id, like the two-factor lock and unlike the login lock: the caller is
        // already authenticated, so there is a resolved account here and no enumeration concern.
        if ($this->lockouts?->locked('confirm', $subject, $this->guard)) {
            $this->throwLocked($subject);
        }

        // Reserved before the credential check, for the same reason as the login path: reading
        // `locked()` and counting afterwards lets N concurrent requests each get a verification.
        if ($this->lockouts !== null
            && $this->lockouts->recordFailure('confirm', $subject, $this->guard) > $this->lockouts->maxAttempts()) {
            $this->throwLocked($subject);
        }

        if (! $this->users->validateCredentials($user, ['password' => $password])) {
            throw ValidationException::withMessages(['password' => [__('The provided password is incorrect.')]]);
        }

        // "Consecutive" is the whole point of the cap: any success ends the run — which also
        // returns the slot reserved above, so a correct password never costs the user an attempt.
        $this->lockouts?->release('confirm', $subject, $this->guard);
    }

    private function throwLocked(string $subject): never
    {
        $seconds = $this->lockouts?->availableIn('confirm', $subject, $this->guard);

        throw ValidationException::withMessages([
            'password' => [$seconds === null
                ? __('This account is locked. Contact support to restore access.')
                : __('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)])],
        ])->status(423);
    }
}
