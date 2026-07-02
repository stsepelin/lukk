<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;

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
     * @param  array{password_reset:array{revoke_sessions?:bool,broker?:string},...}  $config
     */
    public function __construct(
        private readonly RevokeAllSessions $revokeAllSessions,
        private readonly array $config,
    ) {}

    /**
     * @param  array{email:string,token:string,password:string}  $credentials
     */
    public function __invoke(array $credentials): void
    {
        $status = Password::broker($this->config['password_reset']['broker'] ?? null)->reset($credentials, function ($user, string $password): void {
            $user->forceFill(['password' => Hash::make($password)])->save();

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
