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
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private readonly array $config,
        private readonly Denylist $denylist,
    ) {
        $this->keys = new KeyRing($config);
    }

    /** @return (\stdClass&object{sub: mixed, jti: mixed, exp: mixed, fid?: mixed, scope?: mixed, pin?: mixed, iss?: mixed, aud?: mixed})|null */
    public function verify(string $jwt): ?object
    {
        JWT::$leeway = $this->config['leeway'] ?? 5;

        // Non-null so firebase/php-jwt populates it with the verified header.
        $headers = new \stdClass;

        try {
            // One Key (symmetric) or a kid-addressed set (asymmetric), decoded under the pinned alg.
            $claims = JWT::decode($jwt, $this->keys->verificationKeys(), $headers);
        } catch (Throwable) {
            return null;
        }

        // Reject non-access tokens: a 2FA/step-up challenge shares key/iss/aud, so `typ` is the only distinguisher.
        // Both spellings RFC 9068 §4 step 1 permits, case-insensitively: a co-issuer in a verify-only
        // topology that stamps the registered long form had 100% of its tokens refused with no diagnostic.
        if (isset($headers->crit)) {
            return null;
        }

        $declared = $headers->typ ?? null;
        $typ = is_string($declared) ? strtolower($declared) : null;

        if ($typ !== 'at+jwt' && $typ !== 'application/at+jwt') {
            return null;
        }

        // Fails CLOSED with no configured issuer, matching `ChallengeToken::decode`. Compared as
        // `null !== null` this passed, so under a per-guard `env()` that is unset — or a config cached
        // before the key existed — `iss` stopped being validated at all.
        $issuer = $this->config['issuer'] ?? null;

        if ($issuer === null || ($claims->iss ?? null) !== $issuer) {
            return null;
        }

        // Accept when this service is one of the token's audiences (string or array).
        $accepted = array_filter((array) ($this->config['audience'] ?? []));
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

        /** @var (\stdClass&object{sub: mixed, jti: mixed, exp: mixed, fid?: mixed, scope?: mixed, pin?: mixed, iss?: mixed, aud?: mixed}) $claims */
        return $claims;
    }
}
