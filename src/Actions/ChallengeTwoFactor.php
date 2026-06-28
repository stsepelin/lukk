<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Validation\ValidationException;
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

        if ($code !== null && $code !== '' && $this->totp->verify($user->twoFactorSecret(), $code)) {
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
