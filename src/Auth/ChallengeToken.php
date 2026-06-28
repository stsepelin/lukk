<?php

declare(strict_types=1);

namespace Lukk\Auth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Str;
use Lukk\Contracts\Denylist;
use Throwable;

/**
 * Pending-auth primitive shared by the second-factor flows (2FA, passkeys): a
 * short-lived signed JWT returned after the first factor, exchanged at a second
 * endpoint for the real token pair. Header `typ={kind}+challenge`; single-use is
 * enforced via the Denylist (by jti) — a stateless API does not get it for free
 * the way a session does on regenerate.
 */
class ChallengeToken
{
    /**
     * @param  array{secret:string,algorithm:string,issuer:string,audience:string,leeway:int,...}  $config
     */
    public function __construct(
        private readonly array $config,
        private readonly Denylist $denylist,
    ) {}

    public function issue(string $kind, int|string $userId, int $ttl): string
    {
        $now = now()->getTimestamp();

        $payload = [
            'iss' => $this->config['issuer'],
            'aud' => $this->config['audience'],
            'sub' => (string) $userId,
            'jti' => (string) Str::uuid(),
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $ttl,
        ];

        return JWT::encode($payload, $this->config['secret'], $this->config['algorithm'], head: ['typ' => $kind.'+challenge']);
    }

    /**
     * Verify WITHOUT consuming — the subject (user id) or null. Lets a wrong
     * second-factor attempt leave the challenge usable for a retry.
     */
    public function verify(string $kind, string $token): ?string
    {
        $claims = $this->decode($kind, $token);

        return $claims === null ? null : (string) $claims->sub;
    }

    /**
     * Verify and consume (single-use). Returns the subject or null on any failure
     * — bad signature, wrong kind, wrong iss/aud, expired, or already spent.
     */
    public function consume(string $kind, string $token): ?string
    {
        $claims = $this->decode($kind, $token);

        if ($claims === null) {
            return null;
        }

        // Cover the leeway window too: the token still decodes for `leeway`
        // seconds past exp, so the single-use marker must outlive that.
        $this->denylist->revokeJti(
            (string) $claims->jti,
            max(1, (int) $claims->exp - now()->getTimestamp() + (int) $this->config['leeway']),
        );

        return (string) $claims->sub;
    }

    private function decode(string $kind, string $token): ?object
    {
        JWT::$leeway = $this->config['leeway'];

        try {
            $claims = JWT::decode($token, new Key($this->config['secret'], $this->config['algorithm']));
        } catch (Throwable) {
            return null;
        }

        if ($this->headerType($token) !== $kind.'+challenge') {
            return null;
        }

        if (($claims->iss ?? null) !== $this->config['issuer'] || ($claims->aud ?? null) !== $this->config['audience']) {
            return null;
        }

        $jti = (string) ($claims->jti ?? '');

        if ($jti === '' || $this->denylist->has('jti', $jti)) {
            return null;
        }

        return $claims;
    }

    private function headerType(string $token): ?string
    {
        $header = json_decode(base64_decode(strtr(explode('.', $token)[0] ?? '', '-_', '+/')) ?: '{}');

        return $header->typ ?? null;
    }
}
