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
        $secret = $user->twoFactorSecret();

        // `$secret !== null` gates the TOTP branch ONLY, and must not be hoisted above it. Passing
        // `(string) null` to the provider is the hazard — `''` is rejected by the bundled provider
        // but a custom `TwoFactorProvider` need not, so an unreadable secret (an APP_KEY rotation
        // with a swallowed DecryptException) would verify as a successful challenge.
        //
        // Refusing EARLY is the opposite mistake, and worse: recovery codes exist for exactly the
        // case where the authenticator is unusable, which includes the server being unable to read
        // the secret. Their verification does not touch the secret, so a null one must still fall
        // through to them rather than lock the account out of its own escape hatch.
        if ($code !== null && $code !== '' && $secret !== null && $this->totp->verify($secret, $code)) {
            return $user;
        }

        if ($recoveryCode !== null && $recoveryCode !== '' && $user->useRecoveryCode($recoveryCode)) {
            return $user;
        }

        $this->fail();
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
