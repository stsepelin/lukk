<?php

declare(strict_types=1);

namespace Lukk\Concerns;

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Lukk\Support\RecoveryCode;

/**
 * Add to your User model for 2FA. Backed by three columns: `two_factor_secret`
 * (encrypted), `two_factor_recovery_codes` (JSON of hashed codes), and
 * `two_factor_confirmed_at`. The secret is decryptable (the verifier must
 * reproduce the OTP); recovery codes are hashed (never re-displayable).
 */
trait HasTwoFactorAuthentication
{
    /** Keep the (encrypted) secret and (hashed) recovery codes out of the model's array/JSON form. */
    public function initializeHasTwoFactorAuthentication(): void
    {
        $this->mergeHidden(['two_factor_secret', 'two_factor_recovery_codes']);
    }

    public function hasEnabledTwoFactor(): bool
    {
        return ! is_null($this->two_factor_secret) && ! is_null($this->two_factor_confirmed_at);
    }

    public function twoFactorSecret(): ?string
    {
        return is_null($this->two_factor_secret) ? null : Crypt::decryptString($this->two_factor_secret);
    }

    /**
     * Generate a fresh set of recovery codes, store them hashed, and return the
     * plaintext (shown once). Replaces any existing set.
     *
     * @return array<int,string>
     */
    public function generateRecoveryCodes(int $count): array
    {
        $codes = array_map(fn () => RecoveryCode::generate(), range(1, $count));

        $this->forceFill([
            'two_factor_recovery_codes' => json_encode(array_map(fn (string $code) => Hash::make($code), $codes)),
        ])->save();

        return $codes;
    }

    /**
     * How many unused recovery codes remain. The codes are hashed and never
     * re-displayable, so this is the only safe thing to surface — a count for a
     * "codes left" indicator, never the values.
     */
    public function recoveryCodesRemaining(): int
    {
        $codes = json_decode($this->two_factor_recovery_codes ?? '[]', true);

        return is_array($codes) ? count($codes) : 0;
    }

    /**
     * Verify a recovery code and, on a match, consume it (single-use).
     */
    public function useRecoveryCode(string $code): bool
    {
        // Lock the row and re-read inside a transaction so two concurrent
        // redemptions can't both spend the same single-use code.
        return DB::transaction(function () use ($code) {
            static::query()->whereKey($this->getKey())->lockForUpdate()->first();
            $this->refresh();

            $hashes = json_decode($this->two_factor_recovery_codes ?? '[]', true) ?: [];

            foreach ($hashes as $index => $hash) {
                if (Hash::check($code, $hash)) {
                    unset($hashes[$index]);
                    $this->forceFill(['two_factor_recovery_codes' => json_encode(array_values($hashes))])->save();

                    return true;
                }
            }

            return false;
        });
    }
}
