<?php

declare(strict_types=1);

namespace Lukk\Tokens\Jwt;

use Firebase\JWT\JWT;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\TokenVerifier;
use Throwable;

/**
 * Default TokenVerifier (firebase/php-jwt).
 *  - Algorithm pinned via the KeyRing (every Key carries the configured alg):
 *    blocks alg-confusion and rejects alg=none. The alg is never read from the
 *    token header.
 *  - exp/nbf/iat validated by the library (with leeway).
 *  - iss/aud asserted explicitly.
 *  - jti and fid checked against the denylist.
 * Returns claims, or null on any failure (no reason leaked).
 */
class FirebaseTokenVerifier implements TokenVerifier
{
    private readonly KeyRing $keys;

    /**
     * @param  array{algorithm:string,secret:string,issuer:string,audience:string|array<int,string>,leeway:int,...}  $config
     */
    public function __construct(
        private readonly array $config,
        private readonly Denylist $denylist,
    ) {
        $this->keys = new KeyRing($config);
    }

    public function verify(string $jwt): ?object
    {
        JWT::$leeway = $this->config['leeway'];

        // Non-null so firebase/php-jwt populates it with the verified header.
        $headers = new \stdClass;

        try {
            // One Key (symmetric) or a kid-addressed set (asymmetric), decoded under the pinned alg.
            $claims = JWT::decode($jwt, $this->keys->verificationKeys(), $headers);
        } catch (Throwable) {
            return null;
        }

        // Reject non-access tokens: a 2FA/step-up challenge shares key/iss/aud, so `typ` is the only distinguisher.
        if (($headers->typ ?? null) !== 'at+jwt') {
            return null;
        }

        if (($claims->iss ?? null) !== $this->config['issuer']) {
            return null;
        }

        // Accept when this service is one of the token's audiences (string or array).
        $accepted = array_filter((array) $this->config['audience']);
        $presented = array_filter((array) ($claims->aud ?? []));

        if (! array_intersect($presented, $accepted)) {
            return null;
        }

        // Require exp explicitly: the library only validates it when present.
        if (! is_numeric($claims->exp ?? null)) {
            return null;
        }

        // Require a non-empty string sub before handing it to the user provider.
        if (! is_string($claims->sub ?? null) || $claims->sub === '') {
            return null;
        }

        if ($this->denylist->hasAny(['jti' => (string) ($claims->jti ?? ''), 'fid' => (string) ($claims->fid ?? '')])) {
            return null;
        }

        return $claims;
    }
}
