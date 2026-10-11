<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Timebox;
use Illuminate\Validation\ValidationException;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Events\PasskeyDeleted;

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
    public function __invoke(#[\SensitiveParameter] array $credentials): void
    {
        // Boxed for the reason forgot-password is. Every failure answers the same 422, but a known address
        // with a pending token row pays a bcrypt `Hash::check` of the presented token that an unknown one
        // does not — and the broker's own box (`auth.timebox_duration`, 200 ms) is shorter than one
        // derivation at cost 12, and a Timebox never claws back an overrun. So the response TIME said
        // which addresses had an account. A success returns early: its status code already says it.
        // Cast: a published config can carry an uncast `env()`, and `Timebox::call()` takes an int.
        $status = app(Timebox::class)->call(function (Timebox $timebox) use ($credentials) {
            $status = $this->reset($credentials);

            if ($status === Password::PASSWORD_RESET) {
                $timebox->returnEarly();
            }

            return $status;
        }, (int) ($this->config['password_reset']['timebox_micros'] ?? 1_000_000));

        if ($status !== Password::PASSWORD_RESET) {
            // One generic message for every failure (bad/expired token, unknown user).
            // The broker distinguishes INVALID_USER from INVALID_TOKEN, and
            // surfacing that difference would let this endpoint enumerate accounts — the
            // very thing forgot-password's generic 200 is careful to avoid.
            throw ValidationException::withMessages(['email' => [__('passwords.token')]]);
        }
    }

    /**
     * @param  array{email:string,token:string,password:string}  $credentials
     */
    private function reset(#[\SensitiveParameter] array $credentials): mixed
    {
        return Password::broker($this->config['password_reset']['broker'] ?? null)->reset($credentials, function ($user, string $password): void {
            // The column the model names (`getAuthPasswordName()`), as sign-in reads it.
            $user->forceFill([$user->getAuthPasswordName() => Hash::make($password)])->save();

            // The only self-service way out of a lock. A reset proves control of the address —
            // strictly stronger evidence than the password itself — so leaving the account locked
            // after it would mean the user does the one thing the product offers and is still
            // stuck, with no path left but a support ticket.
            // Keyed off the RESOLVED user, which is also what the failure path records — so this
            // releases exactly this account's lock and no one else's. Releasing on the normalized
            // identifier instead meant a look-alike account (`аdmin@` with a Cyrillic а) shared the
            // row, and resetting either password cleared the other's lock.
            // (The identifier argument is unused when a user is passed.)
            // Both of its counters: the account's, and the fold of its own identifier, which login also
            // counts (`LoginRateLimiter::lockoutSubjects()`).
            foreach (LoginRateLimiter::subjectsOf($user) as $subject) {
                $this->lockouts?->release('login', $subject, $this->guard);
            }
            // The step-up lock counts failures against the password that just changed, so those
            // failures are now meaningless. Keyed on the id, which is how the confirm lock records.
            $this->lockouts?->release('confirm', (string) $user->getAuthIdentifier(), $this->guard);

            event(new PasswordReset($user));

            if ($this->config['password_reset']['revoke_sessions'] ?? true) {
                ($this->revokeAllSessions)($user->getAuthIdentifier());
            }

            if ($this->config['password_reset']['revoke_passkeys'] ?? false) {
                $this->revokePasskeys($user);
            }
        });
    }

    /**
     * Opt-in: a reset that also removes every passkey, each announced as `PasskeyDeleted`. Off by
     * default, as the second factor survives a reset too (NIST SP 800-63B-4 §4.2 asks for neither); on,
     * a passkey an attacker enrolled while holding the password, or on a squatted account, does not
     * outlive the recovery. An unpublished passkeys table is the database store's to answer (it has
     * none to list), so a rebound store is covered too.
     */
    private function revokePasskeys(Authenticatable $user): void
    {
        $passkeys = app(PasskeyRepository::class);

        foreach ($passkeys->summariesForUser($user->getAuthIdentifier()) as $summary) {
            if ($passkeys->delete($user->getAuthIdentifier(), $summary['credential_id'])) {
                event(new PasskeyDeleted($user, $summary['credential_id']));
            }
        }
    }
}
