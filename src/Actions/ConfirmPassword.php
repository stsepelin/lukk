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
            $seconds = $this->lockouts->availableIn('confirm', $subject, $this->guard);

            throw ValidationException::withMessages([
                'password' => [$seconds === null
                    ? __('This account is locked. Contact support to restore access.')
                    : __('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)])],
            ])->status(423);
        }

        if (! $this->users->validateCredentials($user, ['password' => $password])) {
            $this->lockouts?->recordFailure('confirm', $subject, $this->guard);

            throw ValidationException::withMessages(['password' => [__('The provided password is incorrect.')]]);
        }

        // "Consecutive" is the whole point of the cap: any success ends the run.
        $this->lockouts?->release('confirm', $subject, $this->guard);
    }
}
