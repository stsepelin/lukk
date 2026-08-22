<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Validation\ValidationException;
use Lukk\Contracts\TwoFactorAuthenticatable;
use Lukk\Contracts\TwoFactorProvider;

/**
 * Resolve the challenged user and verify their second factor — a TOTP code or a
 * single-use recovery code. Returns the user or throws.
 */
class ChallengeTwoFactor
{
    public function __construct(
        private readonly UserProvider $users,
        private readonly TwoFactorProvider $totp,
    ) {}

    public function __invoke(int|string $userId, ?string $code, ?string $recoveryCode): Authenticatable
    {
        $user = $this->users->retrieveById($userId);

        if ($user === null || ! $this->enabled($user)) {
            $this->fail();
        }

        /** @var Authenticatable&TwoFactorAuthenticatable $user */
        // Resolved LAZILY, inside the TOTP branch. Reading it eagerly threw on the very case this
        // guard exists for: the bundled trait decrypts, and `Crypt::decryptString()` THROWS
        // `DecryptException` on a stale APP_KEY rather than returning null — so an eager read never
        // reached the recovery branch at all. It also escaped `VerifyTwoFactorChallenge`, which
        // catches only `ValidationException`, leaving the reserved lockout slot un-released: a 500
        // per attempt and a permanent lock.
        //
        // A recovery-only attempt must never touch the secret. That is the whole point of recovery
        // codes — the authenticator is unusable, and "the server cannot read your secret" is one of
        // the ways that happens.
        if ($code !== null && $code !== '') {
            $secret = $this->secretOf($user);

            // `''` as well as null: an empty key is what the old `(string) null` cast produced, the
            // bundled provider rejects it but a custom `TwoFactorProvider` need not, and a consumer
            // catching `DecryptException` and returning `''` is the obvious reflex.
            if ($secret !== null && $secret !== '' && $this->totp->verify($secret, $code)) {
                return $user;
            }
        }

        if ($recoveryCode !== null && $recoveryCode !== '' && $user->useRecoveryCode($recoveryCode)) {
            return $user;
        }

        $this->fail();
    }

    /**
     * The TOTP secret, or null when it cannot be read.
     *
     * `twoFactorSecret()` is consumer-overridable and the bundled implementation decrypts, so it can
     * throw as easily as it can return null. Both mean the same thing here — no usable second factor
     * — and neither may take down the recovery path.
     *
     * Typed `Authenticatable` at RUNTIME, narrowed only in PHPDoc: `TwoFactorAuthenticatable` is a
     * documentation contract, and a consumer whose model uses the trait without implementing the
     * interface must keep working. Hinting it here broke exactly that.
     *
     * @param  Authenticatable&TwoFactorAuthenticatable  $user
     */
    private function secretOf(Authenticatable $user): ?string
    {
        try {
            return $user->twoFactorSecret();
        } catch (\Throwable) {
            return null;
        }
    }

    private function enabled(Authenticatable $user): bool
    {
        return method_exists($user, 'hasEnabledTwoFactor') && $user->hasEnabledTwoFactor();
    }

    private function fail(): never
    {
        throw ValidationException::withMessages(['code' => [__('The provided two-factor code was invalid.')]]);
    }
}
