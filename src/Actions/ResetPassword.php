<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Contracts\LockoutRepository;

/**
 * Reset a password via Laravel's password broker (single-use, hashed, expiring token). On
 * success it sets the new password, fires `Illuminate\Auth\Events\PasswordReset`, and — unless
 * `password_reset.revoke_sessions` is false — revokes every existing session (refresh families
 * + denylist), so a session that predates the reset (e.g. an attacker's) can't survive it. Any
 * failure (invalid/expired token, unknown user) throws one generic `422` — the same message for
 * every case, so the endpoint can't be used to enumerate accounts.
 */
class ResetPassword
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private readonly RevokeAllSessions $revokeAllSessions,
        private readonly array $config,
        // Null unless `features.lockout` is on.
        private readonly ?LockoutRepository $lockouts = null,
        private readonly ?string $guard = null,
    ) {}

    /**
     * @param  array{email:string,token:string,password:string}  $credentials
     */
    public function __invoke(array $credentials): void
    {
        $status = Password::broker($this->config['password_reset']['broker'] ?? null)->reset($credentials, function ($user, string $password): void {
            $user->forceFill(['password' => Hash::make($password)])->save();

            // The only self-service way out of a lock. A reset proves control of the address —
            // strictly stronger evidence than the password itself — so leaving the account locked
            // after it would mean the user does the one thing the product offers and is still
            // stuck, with no path left but a support ticket.
            // Keyed off the RESOLVED user, which is also what the failure path records — so this
            // releases exactly this account's lock and no one else's. Releasing on the normalized
            // identifier instead meant a look-alike account (`аdmin@` with a Cyrillic а) shared the
            // row, and resetting either password cleared the other's lock.
            $this->lockouts?->release('login', LoginRateLimiter::lockoutSubject($user, ''), $this->guard);
            // The step-up lock counts failures against the password that just changed, so those
            // failures are now meaningless. Keyed on the id, which is how the confirm lock records.
            $this->lockouts?->release('confirm', (string) $user->getAuthIdentifier(), $this->guard);

            event(new PasswordReset($user));

            if ($this->config['password_reset']['revoke_sessions'] ?? true) {
                ($this->revokeAllSessions)($user->getAuthIdentifier());
            }
        });

        if ($status !== Password::PASSWORD_RESET) {
            // One generic message for every failure (bad/expired token, unknown user,
            // throttled). The broker distinguishes INVALID_USER from INVALID_TOKEN, and
            // surfacing that difference would let this endpoint enumerate accounts — the
            // very thing forgot-password's generic 200 is careful to avoid.
            throw ValidationException::withMessages(['email' => [__('passwords.token')]]);
        }
    }
}
