<?php

declare(strict_types=1);

namespace Lukk\Concerns;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Lukk\Support\RecoveryCode;

/**
 * Add to your User model for 2FA. Backed by three columns: `two_factor_secret`
 * (encrypted), `two_factor_recovery_codes` (JSON of hashed codes), and
 * `two_factor_confirmed_at`. The secret is decryptable (the verifier must
 * reproduce the OTP); recovery codes are hashed (never re-displayable).
 *
 * @property ?string $two_factor_secret encrypted TOTP secret
 * @property ?string $two_factor_recovery_codes JSON list of password-hashed (salted) codes, not encrypted
 * @property ?Carbon $two_factor_confirmed_at
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
        // Clamped, like the lockout's max_attempts. `range(1, 0)` counts DOWN and returns [1, 0],
        // so a configured 0 silently produced two codes, and a negative value produced |n|+1 — the
        // opposite of what was asked for either way.
        $count = RecoveryCode::setSize($count);

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
    public function useRecoveryCode(#[\SensitiveParameter] string $code): bool
    {
        // Find the match BEFORE taking the lock. One password-hash derivation per stored code — up to
        // a hundred — held the user's row under `lockForUpdate()` for seconds on every wrong guess,
        // stalling every other write to the account. Verifying needs no lock; spending does.
        $match = null;

        foreach ($this->recoveryCodeHashes() as $hash) {
            // A code stored under a hasher the app has since left (bcrypt, after a move to argon2id with
            // `verify` on) makes the check THROW; it is no match, as sign-in treats such a password,
            // rather than a 500 on the one path left to a user who lost their authenticator.
            try {
                $matches = Hash::check($code, $hash);
            } catch (\Throwable) {
                $matches = false;
            }

            if ($matches) {
                $match = $hash;

                break;
            }
        }

        if ($match === null) {
            return false;
        }

        // Lock, re-read and spend by VALUE: a concurrent redemption may have spent this code (or
        // another) since the read above, so it is spent only if it is still there.
        // On the user's OWN connection: a directory database is supported, and a transaction on the default
        // one would leave this lock in autocommit, released at once — two redemptions could both spend it.
        return $this->getConnection()->transaction(function () use ($match) {
            static::query()->whereKey($this->getKey())->lockForUpdate()->first();
            $this->refresh();

            $hashes = $this->recoveryCodeHashes();
            $index = array_search($match, $hashes, true);

            if ($index === false) {
                return false;
            }

            unset($hashes[$index]);
            $this->forceFill(['two_factor_recovery_codes' => json_encode(array_values($hashes))])->save();

            return true;
        });
    }

    /** @return array<array-key, mixed> the stored hashes, listed or keyed */
    private function recoveryCodeHashes(): array
    {
        return json_decode($this->two_factor_recovery_codes ?? '[]', true) ?: [];
    }
}
