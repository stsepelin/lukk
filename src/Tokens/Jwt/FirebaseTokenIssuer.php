<?php

declare(strict_types=1);

namespace Lukk\Tokens\Jwt;

use Firebase\JWT\JWT;
use Illuminate\Support\Str;
use Lukk\Contracts\TokenIssuer;
use Lukk\Lukk;
use Lukk\Support\Abilities;
use Lukk\Support\TokenContext;

/**
 * Default TokenIssuer (firebase/php-jwt). Access tokens carry iss/aud/sub/fid/
 * jti/iat/nbf/exp + header typ=at+jwt. Refresh secrets are opaque 256-bit.
 */
class FirebaseTokenIssuer implements TokenIssuer
{
    private readonly KeyRing $keys;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(private readonly array $config)
    {
        $this->keys = new KeyRing($config);
    }

    public function accessToken(TokenContext $context, array $claims = [], ?Abilities $abilities = null): array
    {
        $now = now()->getTimestamp();
        $jti = (string) Str::uuid();

        $standard = [
            'iss' => $this->config['issuer'],
            'aud' => $this->audience(),
            'sub' => (string) $context->userId,
            'fid' => $context->familyId,
            'jti' => $jti,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $this->config['access_ttl'],
        ];

        // Standard claims always win. `$claims` arrives already ordered by the calling Action —
        // per-login values over `tokenClaimsUsing`'s — because resolving the hook HERE ran
        // application code inside the rotate transaction's row lock, the very thing moving abilities
        // out was meant to stop.
        $payload = array_merge($claims, $standard);

        // `scope` (RFC 6749 §3.3 / RFC 9068 §2.2.3) — space-delimited, so a non-lukk verifier or an
        // API gateway can read it.
        //
        // RESERVED once the abilities layer owns it, and applied AFTER the merge so neither
        // `tokenClaimsUsing` nor a per-login `$claims` array can forge or retain one. That
        // direction matters in both senses: a hook could previously grant itself `admin.*`, and —
        // worse — an EMPTY grant failed to erase a hook's claim, so `abilitiesUsing` returning `[]`
        // for a suspended user still minted `admin.*`. The authorization layer said "deny
        // everything" and the token came out privileged. An empty grant must be able to erase.
        //
        // Untouched when the feature was never configured, so an install that hasn't opted in keeps
        // whatever `tokenClaimsUsing` was doing in 0.5.0.
        //
        // The issuer does not DERIVE abilities — it stamps the grant the Action hands it. Resolving
        // `abilitiesUsing` here put policy inside a documented swap seam: rebinding `TokenIssuer`
        // silently dropped `scope`, and since the gates deny by default, every gated route then
        // answered 403 with nothing to explain it. It also meant the callback ran under the rotate
        // transaction's row lock.
        if ($abilities !== null) {
            unset($payload['scope']);

            if (($scope = $abilities->toScope()) !== null) {
                $payload['scope'] = $scope;
            }
        }

        // `pin` is RESERVED on the same reasoning as `scope`, and unset unconditionally rather than
        // merged: a standard claim only wins the merge where it has a key, and this one is absent
        // for a derived token — so a `tokenClaimsUsing` hook could stamp `pin` on an ordinary
        // session and lukk would treat it as a machine token, silently taking session management
        // away from a real user. Only ever present when true, so an ordinary token stays
        // byte-identical to 0.5.0.
        unset($payload['pin']);

        if ($context->pinned) {
            $payload['pin'] = true;
        }

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
