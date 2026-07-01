<?php

declare(strict_types=1);

namespace Lukk\Tokens\Jwt;

use Firebase\JWT\Key;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;

/**
 * Resolves signing / verification material from config, hiding the two cases
 * behind one interface:
 *
 *  - **symmetric** (`HS*`) — one shared secret signs and verifies; no `kid`.
 *  - **asymmetric** (`RS*`/`ES*`) — a private key signs (stamping the active
 *    `kid`), and a `kid`-addressed set of public keys verifies, so a retired
 *    key can keep verifying its still-live tokens during a rotation overlap.
 *
 * The algorithm is always taken from config and pinned onto every `Key`; it is
 * never read from a token header — the RS256↔HS256 confusion defense.
 */
class KeyRing
{
    /**
     * @param  array{algorithm:string,secret:?string,keys?:array<string,mixed>}  $config
     */
    public function __construct(private readonly array $config) {}

    public function isSymmetric(): bool
    {
        return str_starts_with($this->config['algorithm'], 'HS');
    }

    /**
     * The key to sign with, plus the `kid` to stamp (null when symmetric).
     *
     * @return array{key: string|OpenSSLAsymmetricKey, kid: ?string}
     */
    public function signingKey(): array
    {
        if ($this->isSymmetric()) {
            return ['key' => (string) $this->config['secret'], 'kid' => null];
        }

        // Fail loud: signing with a kid absent from the public set mints tokens nothing can verify.
        $kid = (string) ($this->config['keys']['active'] ?? '');

        if ($kid === '' || ! array_key_exists($kid, $this->publicKeys())) {
            throw new InvalidArgumentException("lukk.keys.active ('{$kid}') must be non-empty and present in lukk.keys.public to sign {$this->config['algorithm']} tokens.");
        }

        return ['key' => $this->privateKey(), 'kid' => $kid];
    }

    /**
     * The key(s) to verify with: a single `Key` when symmetric, or a `kid`-keyed
     * map when asymmetric (the rotation set).
     *
     * @return Key|array<string, Key>
     */
    public function verificationKeys(): Key|array
    {
        if ($this->isSymmetric()) {
            return new Key((string) $this->config['secret'], $this->config['algorithm']);
        }

        $keys = [];

        foreach ($this->publicKeys() as $kid => $pem) {
            $keys[$kid] = new Key($pem, $this->config['algorithm']);
        }

        return $keys;
    }

    /**
     * The public keys (PEM), keyed by `kid` — for verification and the JWKS.
     *
     * @return array<string, string>
     */
    public function publicKeys(): array
    {
        $keys = [];

        foreach ((array) ($this->config['keys']['public'] ?? []) as $kid => $value) {
            $pem = $this->load($value);

            if ($pem !== '') {
                $keys[(string) $kid] = $pem;
            }
        }

        return $keys;
    }

    /**
     * The public keys as a JWK Set (RFC 7517) for a JWKS endpoint. Built from the
     * key material with openssl — no extra dependency. Empty when symmetric.
     *
     * @return array{keys: array<int, array<string, string>>}
     */
    public function jwks(): array
    {
        // A symmetric algorithm publishes no public keys.
        if ($this->isSymmetric()) {
            return ['keys' => []];
        }

        $jwks = [];

        foreach ($this->publicKeys() as $kid => $pem) {
            $jwk = $this->toJwk($pem);

            if ($jwk !== null) {
                $jwks[] = ['kid' => (string) $kid, 'use' => 'sig', 'alg' => $this->config['algorithm']] + $jwk;
            }
        }

        return ['keys' => $jwks];
    }

    /**
     * One public key → its JWK members. The key type follows the configured
     * algorithm (EC for ES*, RSA otherwise); a malformed key yields null.
     *
     * @return array<string, string>|null
     */
    private function toJwk(string $pem): ?array
    {
        $public = @openssl_pkey_get_public($pem);

        if ($public === false) {
            return null;
        }

        $details = openssl_pkey_get_details($public);

        if (str_starts_with($this->config['algorithm'], 'ES')) {
            // [JWK curve name, field size in bytes]. openssl strips leading zero bytes
            // from x/y, but RFC 7518 §6.2.1.2 requires each coordinate to be the full
            // field length, left-padded — else a ~1/256 short coordinate breaks strict
            // JWKS consumers.
            $curves = ['prime256v1' => ['P-256', 32], 'secp384r1' => ['P-384', 48], 'secp521r1' => ['P-521', 66]];
            [$crv, $size] = $curves[$details['ec']['curve_name']] ?? [(string) $details['ec']['curve_name'], null];
            $pad = fn (string $coord): string => $size === null ? $coord : str_pad($coord, $size, "\0", STR_PAD_LEFT);

            return [
                'kty' => 'EC',
                'crv' => $crv,
                'x' => $this->base64Url($pad($details['ec']['x'])),
                'y' => $this->base64Url($pad($details['ec']['y'])),
            ];
        }

        return [
            'kty' => 'RSA',
            'n' => $this->base64Url($details['rsa']['n']),
            'e' => $this->base64Url($details['rsa']['e']),
        ];
    }

    private function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private function privateKey(): string|OpenSSLAsymmetricKey
    {
        $pem = $this->load($this->config['keys']['private'] ?? '');
        $passphrase = $this->config['keys']['passphrase'] ?? null;

        if ($passphrase !== null && $passphrase !== '') {
            $key = openssl_pkey_get_private($pem, (string) $passphrase);

            // Fail loud rather than hand an undecryptable PEM to the signer.
            if ($key === false) {
                throw new InvalidArgumentException('Could not decrypt the private key — check lukk.keys.passphrase.');
            }

            return $key;
        }

        return $pem;
    }

    /**
     * Accept either an inline PEM or a path to one (`@/path` or a bare path), so
     * keys can live in env or in a secrets-mounted file.
     */
    private function load(mixed $value): string
    {
        $value = (string) $value;

        if ($value === '') {
            return '';
        }

        if (str_contains($value, '-----BEGIN')) {
            return $value;
        }

        $path = str_starts_with($value, '@') ? substr($value, 1) : $value;

        return is_file($path) ? (string) file_get_contents($path) : '';
    }
}
