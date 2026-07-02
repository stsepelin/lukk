<?php

declare(strict_types=1);

namespace Lukk\TwoFactor;

use Illuminate\Contracts\Cache\Repository;
use Lukk\Contracts\TwoFactorProvider;
use PragmaRX\Google2FA\Google2FA;

/**
 * Default TOTP provider (pragmarx/google2fa). Profile SHA1 / 6 digits / 30s — the
 * only one mainstream authenticator apps reliably support. Secret is a 160-bit
 * base32 seed; verification tolerates ±`window` steps of drift and rejects reuse
 * of a code within its window (replay defense — the intra-window code-reuse class, CVE-2022-25838).
 */
class Google2FaTotpProvider implements TwoFactorProvider
{
    /**
     * @param  array{issuer:string,window:int}  $config
     */
    public function __construct(
        private readonly Google2FA $engine,
        private readonly Repository $cache,
        private readonly array $config,
    ) {}

    public function generateSecret(): string
    {
        return $this->engine->generateSecretKey(32); // 32 base32 chars = 160-bit seed
    }

    public function otpauthUri(string $holder, string $secret): string
    {
        return $this->engine->getQRCodeUrl($this->config['issuer'], $holder, $secret);
    }

    public function verify(string $secret, string $code): bool
    {
        if (! $this->engine->verifyKey($secret, $code, $this->config['window'])) {
            return false;
        }

        $key = 'lukk:2fa:used:'.hash('sha256', $secret.'|'.$code);

        // Atomic claim: add() writes only if the key is absent and returns false otherwise,
        // so two concurrent requests presenting the same code can't both pass (has()+put()
        // would race). The marker outlives the code's full validity band (±window steps).
        return $this->cache->add($key, true, (2 * $this->config['window'] + 1) * 30);
    }
}
