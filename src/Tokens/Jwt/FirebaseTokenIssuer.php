<?php

declare(strict_types=1);

namespace Lukk\Tokens\Jwt;

use Firebase\JWT\JWT;
use Illuminate\Support\Str;
use Lukk\Contracts\TokenIssuer;
use Lukk\Lukk;

/**
 * Default TokenIssuer (firebase/php-jwt). Access tokens carry iss/aud/sub/fid/
 * jti/iat/nbf/exp + header typ=at+jwt. Refresh secrets are opaque 256-bit.
 */
class FirebaseTokenIssuer implements TokenIssuer
{
    private readonly KeyRing $keys;

    /**
     * @param  array{algorithm:string,secret:string,issuer:string,audience:string|array<int,string>,access_ttl:int,...}  $config
     */
    public function __construct(private readonly array $config)
    {
        $this->keys = new KeyRing($config);
    }

    public function accessToken(int|string $userId, string $familyId, array $claims = []): array
    {
        $now = now()->getTimestamp();
        $jti = (string) Str::uuid();

        $standard = [
            'iss' => $this->config['issuer'],
            'aud' => $this->audience(),
            'sub' => (string) $userId,
            'fid' => $familyId,
            'jti' => $jti,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $this->config['access_ttl'],
        ];

        $custom = Lukk::$tokenClaimsUsing !== null ? (Lukk::$tokenClaimsUsing)($userId) : [];

        // Standard claims always win; per-login claims ($claims) win over the hook.
        $payload = array_merge($custom, $claims, $standard);

        $signing = $this->keys->signingKey();

        $token = JWT::encode(
            $payload,
            $signing['key'],
            $this->config['algorithm'],
            keyId: $signing['kid'],
            head: ['typ' => 'at+jwt'],
        );

        return ['token' => $token, 'jti' => $jti, 'expires_in' => $this->config['access_ttl']];
    }

    /**
     * The "aud" claim. A single audience is stamped as a string (the common
     * case); multiple audiences — a service mesh sharing one issuer — as an
     * array, per RFC 7519 §4.1.3.
     *
     * @return string|array<int, string>
     */
    private function audience(): string|array
    {
        $audiences = array_values(array_filter((array) $this->config['audience']));

        return count($audiences) === 1 ? $audiences[0] : $audiences;
    }

    public function newRefreshSecret(): string
    {
        return bin2hex(random_bytes(32));
    }

    public function hash(string $secret): string
    {
        return hash('sha256', $secret);
    }
}
