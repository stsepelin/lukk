<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\Concerns\CountsLockoutAttempts;
use Lukk\Actions\Concerns\ThrowsWhenLocked;
use Lukk\Contracts\LockoutRepository;
use Lukk\Support\HashablePassword;

/**
 * Re-verify the authenticated user's password for a step-up ("sudo") confirmation.
 *
 * This checks the SAME secret as login, so it needs the same defences: the route is throttled
 * (`lukk-confirm`, per user and per IP), and — when `features.lockout` is on — a run of failures
 * here counts toward the same NIST SP 800-63B-4 §3.2.2 cap. Without both, a caller holding an access
 * token had an unmetered password oracle sitting behind the sudo gate.
 */
class ConfirmPassword
{
    use CountsLockoutAttempts;
    use ThrowsWhenLocked;

    public function __construct(
        private readonly UserProvider $users,
        // Null unless `features.lockout` is on.
        private readonly ?LockoutRepository $lockouts = null,
        private readonly ?string $guard = null,
    ) {}

    public function __invoke(Authenticatable $user, #[\SensitiveParameter] string $password): void
    {
        $subject = (string) $user->getAuthIdentifier();

        // Keyed on the user id, like the two-factor lock and unlike the login lock: the caller is
        // already authenticated, so there is a resolved account here and no enumeration concern.
        if ($this->lockouts?->locked('confirm', $subject, $this->guard)) {
            $this->throwLocked('confirm', $subject, 'password');
        }

        // Reserved before the credential check, for the same reason as the login path: reading
        // `locked()` and counting afterwards lets N concurrent requests each get a verification. The
        // lock itself lands only once the check has failed (`CountsLockoutAttempts`).
        if ($this->lockouts !== null
            && $this->reserveAttempt($this->lockouts, 'confirm', $subject) > $this->lockouts->maxAttempts()) {
            $this->throwLocked('confirm', $subject, 'password');
        }

        try {
            $this->verify($user, $password);
        } catch (ValidationException $e) {
            $this->attemptFailed($this->lockouts, 'confirm', $subject);

            throw $e;
        }

        // "Consecutive" is the whole point of the cap: any success ends the run — which also
        // returns the slot reserved above, so a correct password never costs the user an attempt.
        $this->lockouts?->release('confirm', $subject, $this->guard);
    }

    private function verify(Authenticatable $user, #[\SensitiveParameter] string $password): void
    {
        // Under each spelling of it (as typed, then normalized), each check failing closed if the stored
        // hash is one the active hasher refuses; see `HashablePassword::verified()`.
        $verified = HashablePassword::verified($this->users, $user, ['password' => $password]);

        if ($verified === null) {
            throw ValidationException::withMessages(['password' => [__('The provided password is incorrect.')]]);
        }

        // A bcrypt row longer than 72 bytes verifies only in part; see `HashablePassword::mustReset()`.
        if (HashablePassword::verifiesOnlyInPart($user, $verified)) {
            throw HashablePassword::mustReset('password');
        }
    }

    private function lockoutGuard(): ?string
    {
        return $this->guard;
    }
}
