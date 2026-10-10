<?php

declare(strict_types=1);

namespace Lukk\Tokens\Jwt;

use Firebase\JWT\JWT;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\TokenVerifier;
use Lukk\Lukk;
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
    public function verify(#[\SensitiveParameter] string $jwt): ?object
    {
        // Capped at five minutes: RFC 7519 §4.1.4 allows "some small leeway", and `LUKK_LEEWAY=86400`
        // stretched every exp by a day.
        $leeway = Lukk::leeway($this->config);
        JWT::$leeway = $leeway;

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
        // The two filters are a PAIR: each alone changes no outcome, because whichever side keeps a
        // blank entry finds the other side's already removed. Together they stop a blank
        // `LUKK_AUDIENCE=` on both sides from intersecting on '' and admitting a token minted for nobody.
        $accepted = array_filter((array) ($this->config['audience'] ?? [])); // @pest-mutate-ignore: UnwrapArrayFilter

        // RFC 7519 §4.1.3 makes `aud` a StringOrURI or an ARRAY of them. A JSON object decodes to an object,
        // and the `(array)` cast below would turn its property VALUES into a list that intersects.
        if (is_object($claims->aud ?? null)) {
            return null;
        }

        $presented = array_filter((array) ($claims->aud ?? [])); // @pest-mutate-ignore: UnwrapArrayFilter

        // Scalars only, BEFORE `array_intersect`, which compares its elements as strings: a nested
        // array or object in `aud` raised "Array to string conversion" and so a 500, exactly as a
        // non-scalar `jti`/`fid` did below — and two lines earlier, so the guard down there never got
        // the chance. RFC 7519 §4.1.3 makes `aud` a StringOrURI or an array of them; RFC 8725 §3.10
        // says check the type before using it.
        foreach ($presented as $audience) {
            if (! is_scalar($audience)) {
                return null;
            }
        }

        if (! array_intersect($presented, $accepted)) {
            return null;
        }

        // Require exp explicitly: the library only validates it when present. And every time claim must
        // be a NumericDate (RFC 7519 §2) — a fraction is allowed — within a range a timestamp can
        // mean. A co-issuer holding the key could otherwise stamp `exp: 1e30` (or `iat`
        // beside an `nbf`, where the library skips its own iat check), and every later `(int)` cast of
        // it warned into a 500: on logout, on logout-all, and with claim_seconds on, on every request.
        if (! self::isNumericDate($claims->exp ?? null)) {
            return null;
        }

        foreach (['iat', 'nbf'] as $claim) {
            if (property_exists($claims, $claim) && ! self::isNumericDate($claims->{$claim})) {
                return null;
            }
        }

        // Require a non-empty string sub before handing it to the user provider.
        if (! is_string($claims->sub ?? null) || $claims->sub === '') {
            return null;
        }

        // Scalars ONLY, before the casts. `exp` and `sub` above are type-checked for the same reason
        // and these were not: a co-issuer token carrying `"jti": ["a","b"]` raised "Array to string
        // conversion", which `HandleExceptions` promotes to an ErrorException — a 500 on every
        // request presenting it. Worse than the 500, the cast yields the literal `Array`, so the
        // lookup asks for `lukk:dl:fid:Array` and a REVOKED FAMILY stops matching. `ChallengeToken`
        // already hardens exactly this on its own decode path (RFC 8725 §3.10); the asymmetry
        // between the two was unintentional.
        //
        // Reachable only by a co-issuer holding the signing key — the topology this class exists to
        // support. A token whose `jti`/`fid` is not a scalar is not one this package minted.
        if ((isset($claims->jti) && ! is_scalar($claims->jti)) || (isset($claims->fid) && ! is_scalar($claims->fid))) {
            return null;
        }

        // The casts state the contract's `array<string, string>`; `CacheDenylist::hasAny()` casts as
        // well, so a claim another issuer sent as a number reaches the same key either way. The ''
        // is what keeps an absent claim out of the lookup — a placeholder would be MGET'd and miss,
        // same answer, one key more.
        if ($this->denylist->hasAny(['jti' => (string) ($claims->jti ?? ''), 'fid' => (string) ($claims->fid ?? '')])) { // @pest-mutate-ignore: RemoveStringCast,EmptyStringToNotEmpty
            return null;
        }

        /** @var (\stdClass&object{sub: mixed, jti: mixed, exp: mixed, fid?: mixed, scope?: mixed, pin?: mixed, iss?: mixed, aud?: mixed}) $claims */
        return $claims;
    }

    /**
     * A number between the epoch and the end of year 9999 — the range a timestamp can mean. A numeric
     * string is tolerated, as some issuers send one (SessionClaimTest); the range is what matters.
     */
    private static function isNumericDate(mixed $value): bool
    {
        if (! is_numeric($value)) {
            return false;
        }

        $number = (float) $value;

        return is_finite($number) && $number >= 0 && $number <= 253402300799;
    }
}
