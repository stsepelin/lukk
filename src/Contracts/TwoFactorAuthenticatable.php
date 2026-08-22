<?php

declare(strict_types=1);

namespace Lukk\Contracts;

/**
 * What `Concerns\HasTwoFactorAuthentication` provides, named so it can be depended on.
 *
 * Mirrors the {@see HasTokenAbilities} contract/trait pairing. lukk's two-factor actions take an
 * `Authenticatable` at runtime and narrow to this in PHPDoc only — deliberately, so a consumer whose
 * model uses the trait without implementing the interface keeps working exactly as before. Implement
 * it on your user model to get the same guarantee checked in your own static analysis.
 */
interface TwoFactorAuthenticatable
{
    public function hasEnabledTwoFactor(): bool;

    /** The decrypted TOTP secret, or null when two-factor is not set up. */
    public function twoFactorSecret(): ?string;

    /**
     * Replace the recovery codes, returning the PLAINTEXT set — the only time they are readable.
     *
     * @return array<int, string>
     */
    public function generateRecoveryCodes(int $count): array;

    public function recoveryCodesRemaining(): int;

    /** Spend a recovery code. Single-use: a code that verifies is consumed. */
    public function useRecoveryCode(string $code): bool;
}
