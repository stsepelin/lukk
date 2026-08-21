<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\Concerns\ThrowsWhenLocked;
use Lukk\Auth\LoginRateLimiter;
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
 *
 * Requires an ELOQUENT user model: the write is `forceFill()->save()`, neither of which is on the
 * `Authenticatable` contract. Same assumption as `ResetPassword` (and as Fortify), but worth saying
 * out loud for anyone who has swapped `lukk.user_provider` for a non-Eloquent one.
 */
class ChangePassword
{
    use ThrowsWhenLocked;

    public function __construct(
        private readonly UserProvider $users,
        private readonly RevokeOtherSessions $revokeOtherSessions,
        private readonly RevokeAllSessions $revokeAllSessions,
        // Null unless `features.lockout` is on.
        private readonly ?LockoutRepository $lockouts = null,
        private readonly ?string $guard = null,
    ) {}

    public function __invoke(Authenticatable $user, string $current, string $password, ?string $currentFamilyId): void
    {
        $subject = (string) $user->getAuthIdentifier();

        if ($this->lockouts?->locked('confirm', $subject, $this->guard)) {
            $this->throwLocked('confirm', $subject, 'current_password');
        }

        // Reserved before the credential check, like every other password path: reading "is it
        // locked" and counting afterwards lets concurrent requests each get a guess.
        if ($this->lockouts !== null
            && $this->lockouts->recordFailure('confirm', $subject, $this->guard) > $this->lockouts->maxAttempts()) {
            $this->throwLocked('confirm', $subject, 'current_password');
        }

        if (! $this->users->validateCredentials($user, ['password' => $current])) {
            throw ValidationException::withMessages(['current_password' => [__('The provided password is incorrect.')]]);
        }

        $user->forceFill(['password' => Hash::make($password)])->save();

        // BOTH counters. The failures they hold were against a password that no longer exists, and
        // the reset path already releases both for exactly that reason. Releasing only `confirm`
        // left a user who was being brute-forced, noticed, and did the right thing still locked out
        // of login on every other device — permanently, with `release_after` at 0 — and the only
        // way out was the reset email this endpoint exists to avoid. Safe to do here: reaching this
        // line required proving the current password.
        $this->lockouts?->release('confirm', $subject, $this->guard);
        $this->lockouts?->release('login', LoginRateLimiter::lockoutSubject($user, ''), $this->guard);

        // Every OTHER session dies; this one survives. Changing a password is what a user does when
        // they think someone else is in the account, so leaving those sessions alive would defeat
        // the point — but logging the user out of the tab they just did it in is a bad answer to a
        // good instinct. `RevokeOtherSessions` denylists before revoking, so the access tokens stop
        // working immediately rather than at the end of their TTL.
        //
        // With no family id, revoke EVERYTHING. A token carrying no `fid` was not minted by this
        // package's session flow — it comes from a co-issuer sharing the secret, the topology the
        // verify-only config documents — so there is no lukk-tracked session of the caller's among
        // these rows to protect. Skipping the sweep there returned "password-changed" while every
        // session the user believed they had just killed stayed live, and said so nowhere.
        $currentFamilyId === null
            ? ($this->revokeAllSessions)($user->getAuthIdentifier())
            : ($this->revokeOtherSessions)($user->getAuthIdentifier(), $currentFamilyId);

        event(new PasswordChanged($user));
    }

    private function lockoutGuard(): ?string
    {
        return $this->guard;
    }
}
