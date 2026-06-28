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

        // Pass a non-null stdClass so firebase/php-jwt populates it with the
        // verified header (it only fills the ref when it isn't already null).
        $headers = new \stdClass;

        try {
            // A single Key (symmetric) or a kid-addressed set (asymmetric); the
            // library picks by the token's kid and verifies under that key's
            // pinned algorithm.
            $claims = JWT::decode($jwt, $this->keys->verificationKeys(), $headers);
        } catch (Throwable) {
            return null;
        }

        // Reject anything that is not an access token. Challenge tokens (2FA /
        // step-up) are signed with the same key, iss and aud and carry a sub, so
        // the typ header is the only thing distinguishing them — without this an
        // unconsumed 2fa+challenge token could be presented as a bearer token.
        if (($headers->typ ?? null) !== 'at+jwt') {
            return null;
        }

        if (($claims->iss ?? null) !== $this->config['issuer']) {
            return null;
        }

        // Accept when this service is one of the token's audiences. A single
        // audience is a string; a multi-service token carries an array.
        $accepted = array_filter((array) $this->config['audience']);
        $presented = array_filter((array) ($claims->aud ?? []));

        if (! array_intersect($presented, $accepted)) {
            return null;
        }

        // The library validates exp only when it is present; require it so a
        // token lacking exp can never be accepted as non-expiring (defence in
        // depth for any future issuer sharing this iss/aud).
        if (! is_numeric($claims->exp ?? null)) {
            return null;
        }

        // sub is passed straight to the user provider — require a non-empty
        // string so a malformed (null/array) sub can never reach it.
        if (! is_string($claims->sub ?? null) || $claims->sub === '') {
            return null;
        }

        if ($this->denylist->hasAny(['jti' => (string) ($claims->jti ?? ''), 'fid' => (string) ($claims->fid ?? '')])) {
            return null;
        }

        return $claims;
    }
}
