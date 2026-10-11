<?php

declare(strict_types=1);

namespace Lukk\Support;

/**
 * What one verified WebAuthn assertion established.
 *
 * `multiFactor` is the only answer to "may this stand in for a second factor?" — and it is TRUE only
 * when the assertion's UV flag is set AND the stored credential was already `uvInitialized` before
 * this ceremony. WebAuthn L3 §4: "When this is FALSE, including an authentication ceremony where it
 * would be updated to TRUE, the UV flag MUST NOT be relied upon as an authentication factor." The
 * attack that rule exists for is concrete: steal a key that had no PIN, set a PIN on it yourself,
 * and every assertion from then on carries UV.
 *
 * Per ASSERTION, not per configuration: `user_verification` describes what the ceremony asked for,
 * this describes what actually happened. The spec allows relying on it "even when user verification
 * was not required".
 */
class PasskeyAssertion
{
    public function __construct(
        public readonly int $signCount,
        public readonly bool $userVerified,
        public readonly bool $multiFactor,
    ) {}
}
