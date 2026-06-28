<?php

declare(strict_types=1);

namespace Lukk\Contracts;

/**
 * TOTP engine seam. Default: Google2FaTotpProvider (pragmarx/google2fa). Swap to
 * change the algorithm/library without touching the 2FA actions.
 */
interface TwoFactorProvider
{
    /** A fresh base32 shared secret (≥160-bit). */
    public function generateSecret(): string;

    /** The `otpauth://` provisioning URI for an authenticator app / QR. */
    public function otpauthUri(string $holder, string $secret): string;

    /** Verify a submitted code; rejects reuse within the code's window (replay). */
    public function verify(string $secret, string $code): bool;
}
