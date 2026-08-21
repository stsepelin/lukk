<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Lukk\Contracts\LockoutRepository;
use Lukk\Events\PasswordChanged;

/**
 * Change the password of an already-authenticated user, having re-verified the current one.
 *
 * The signed-in counterpart to the forgot-password flow: no email round-trip, because the caller
 * already holds a session and can prove the existing password. That proof is the whole security
 * story — a stolen access token alone must not be enough to take the account over permanently,
 * which is exactly what changing the password would do.
 *
 * So this checks the SAME secret the login route throttles twice over, and is metered the same way:
 * the route carries `lukk-confirm`, and a failed attempt counts toward the `confirm` lockout. It is
 * deliberately the same budget as step-up confirmation rather than a second one — two independent
 * allowances for guessing one password is just a larger allowance.
 */
class ChangePassword
{
    public function __construct(
        private readonly UserProvider $users,
        private readonly RevokeOtherSessions $revokeOtherSessions,
        // Null unless `features.lockout` is on.
        private readonly ?LockoutRepository $lockouts = null,
        private readonly ?string $guard = null,
    ) {}

    public function __invoke(Authenticatable $user, string $current, string $password, ?string $currentFamilyId): void
    {
        $subject = (string) $user->getAuthIdentifier();

        if ($this->lockouts?->locked('confirm', $subject, $this->guard)) {
            $this->throwLocked($subject);
        }

        // Reserved before the credential check, like every other password path: reading "is it
        // locked" and counting afterwards lets concurrent requests each get a guess.
        if ($this->lockouts !== null
            && $this->lockouts->recordFailure('confirm', $subject, $this->guard) > $this->lockouts->maxAttempts()) {
            $this->throwLocked($subject);
        }

        if (! $this->users->validateCredentials($user, ['password' => $current])) {
            throw ValidationException::withMessages(['current_password' => [__('The provided password is incorrect.')]]);
        }

        $user->forceFill(['password' => Hash::make($password)])->save();

        // The counted failures were against a password that no longer exists — and a success ends
        // the run either way. Same reasoning as the reset path.
        $this->lockouts?->release('confirm', $subject, $this->guard);

        // Every OTHER session dies; this one survives. Changing a password is what a user does when
        // they think someone else is in the account, so leaving those sessions alive would defeat
        // the point — but logging the user out of the tab they just did it in is a bad answer to a
        // good instinct. `RevokeOtherSessions` denylists before revoking, so the access tokens stop
        // working immediately rather than at the end of their TTL.
        //
        // With no family id — a caller authenticating by some means that carries none — there is no
        // "current" session to preserve, so nothing is revoked rather than everything: silently
        // logging someone out of the session they are using is worse than leaving the others.
        if ($currentFamilyId !== null) {
            ($this->revokeOtherSessions)($user->getAuthIdentifier(), $currentFamilyId);
        }

        event(new PasswordChanged($user));
    }

    private function throwLocked(string $subject): never
    {
        $seconds = $this->lockouts?->availableIn('confirm', $subject, $this->guard);

        throw ValidationException::withMessages([
            'current_password' => [$seconds === null
                ? __('This account is locked. Contact support to restore access.')
                : __('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)])],
        ])->status(423);
    }
}
