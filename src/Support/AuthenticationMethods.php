<?php

declare(strict_types=1);

namespace Lukk\Support;

/**
 * The `amr` claim's values — every one REGISTERED in the IANA "Authentication Method Reference
 * Values" registry (RFC 8176), so a standard consumer can interpret them.
 *
 * lukk used to emit `webauthn`, which is not in that registry: an RP or gateway reading `amr` could
 * not tell what it meant, and the passkey→2FA path also stamped `pwd` for accounts that have no
 * password at all. The mapping now:
 *
 *  - a password:                         `pwd`
 *  - a passkey (possession of a key):    `pop` + `user` (the UP test every assertion passes). `pop`
 *    rather than `hwk`/`swk` because lukk cannot tell a hardware-secured key from a software one.
 *  - a TOTP or recovery code:            `otp` (RFC 8176 has no separate value for a look-up secret)
 *  - two DIFFERENT factor categories:    `mfa` — a password with an OTP, or a passkey whose user
 *    verification lukk may rely on. Not two possession factors: NIST SP 800-63B-4 §2.2.1 requires a
 *    password or biometric comparison alongside a physical authenticator for AAL2, so a single-factor
 *    passkey plus a TOTP is `pop user otp` and deliberately not `mfa`.
 */
class AuthenticationMethods
{
    public const PASSWORD = 'pwd';

    public const ONE_TIME_PASSWORD = 'otp';

    public const PROOF_OF_POSSESSION = 'pop';

    public const USER_PRESENCE = 'user';

    public const MULTI_FACTOR = 'mfa';

    /** @return list<string> */
    public static function password(): array
    {
        return [self::PASSWORD];
    }

    /** @return list<string> */
    public static function passkey(bool $multiFactor): array
    {
        return $multiFactor
            ? [self::PROOF_OF_POSSESSION, self::USER_PRESENCE, self::MULTI_FACTOR]
            : [self::PROOF_OF_POSSESSION, self::USER_PRESENCE];
    }

    /**
     * A first factor followed by a one-time code. `mfa` only when the first factor was a password —
     * the one combination of these that spans two factor categories.
     *
     * @param  list<string>  $firstFactor
     * @return list<string>
     */
    public static function withOneTimePassword(array $firstFactor): array
    {
        // Spread renumbers the keys `array_diff` keeps, so no `array_values` — an equivalent mutant.
        $methods = [...array_diff($firstFactor, [self::MULTI_FACTOR]), self::ONE_TIME_PASSWORD];

        if (in_array(self::PASSWORD, $methods, true)) {
            $methods[] = self::MULTI_FACTOR;
        }

        return $methods;
    }
}
