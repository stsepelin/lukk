<?php

declare(strict_types=1);
use Firebase\JWT\JWT;
use Illuminate\Support\Arr;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\TokenIssuer;
use Lukk\Lukk;
use Lukk\Tokens\Jwt\FirebaseTokenIssuer;
use Lukk\Tokens\Jwt\FirebaseTokenVerifier;

afterEach(function () {
    Lukk::$tokenClaimsUsing = null;
});

it('verifies a freshly issued access token and exposes its claims', function () {
    $access = issuer()->accessToken(ctx(123, 'fam-1'));
    $claims = claims($access['token']);

    expect($claims)->not->toBeNull()
        ->and($claims->sub)->toBe('123')
        ->and($claims->fid)->toBe('fam-1')
        ->and($claims->iss)->toBe(config('lukk.issuer'))
        ->and($claims->aud)->toBe(config('lukk.audience')[0]); // single audience -> plain string
});

it('rejects an unsigned alg=none token', function () {
    $b64 = fn (array $x) => rtrim(strtr(base64_encode(json_encode($x)), '+/', '-_'), '=');
    $none = $b64(['alg' => 'none', 'typ' => 'JWT']).'.'.$b64([
        'iss' => config('lukk.issuer'), 'aud' => config('lukk.audience'),
        'sub' => '1', 'fid' => 'f', 'jti' => 'j', 'exp' => time() + 100,
    ]).'.';

    expect(verifier()->verify($none))->toBeNull();
});

it('rejects a token minted for a different audience', function () {
    config(['lukk.audience' => 'https://evil.example.com']);
    $access = app(TokenIssuer::class)->accessToken(ctx(1, 'fam'));
    config(['lukk.audience' => 'https://api.example.com']);

    expect(verifier()->verify($access['token']))->toBeNull();
});

it('mints a multi-audience array and accepts it at each listed service', function () {
    // One issuer mints a token intended for two services.
    $config = config('lukk');
    $config['audience'] = ['https://api.example.com', 'https://billing.example.com'];

    $token = (new FirebaseTokenIssuer($config))->accessToken(ctx(1, 'fam'))['token'];

    // The aud claim is the full array (a single audience would stay a string).
    expect((new FirebaseTokenVerifier($config, app(Denylist::class)))->verify($token)?->aud)
        ->toBe(['https://api.example.com', 'https://billing.example.com']);

    // Each service identifies as only itself, and still accepts the token...
    foreach (['https://api.example.com', 'https://billing.example.com'] as $service) {
        $verifier = new FirebaseTokenVerifier(['audience' => $service] + $config, app(Denylist::class));
        expect($verifier->verify($token)?->sub)->toBe('1');
    }

    // ...but a service not in the audience list rejects it.
    $outsider = new FirebaseTokenVerifier(['audience' => 'https://other.example.com'] + $config, app(Denylist::class));
    expect($outsider->verify($token))->toBeNull();
});

it('rejects a challenge token presented as an access token (wrong typ)', function () {
    // 2FA / step-up challenge tokens share the secret, iss, aud and carry a sub;
    // only the typ header distinguishes them. Presenting one as a bearer access
    // token must fail, or it would defeat the second factor.
    $challenge = app(ChallengeToken::class)->issue('2fa', 42, 300);

    expect(verifier()->verify($challenge))->toBeNull();
});

it('rejects a token minted by a different issuer', function () {
    config(['lukk.issuer' => 'https://evil.example.com']);
    $access = app(TokenIssuer::class)->accessToken(ctx(1, 'fam'));
    config(['lukk.issuer' => 'https://api.example.com']);

    expect(verifier()->verify($access['token']))->toBeNull();
});

it('rejects a token whose jti is denylisted', function () {
    $access = issuer()->accessToken(ctx(5, 'fam-x'));
    expect(verifier()->verify($access['token']))->not->toBeNull();

    app(Denylist::class)->revokeJti($access['jti'], 900);

    expect(verifier()->verify($access['token']))->toBeNull();
});

it('rejects an access token whose exp has passed', function () {
    // The issuer stamps exp/nbf from Carbon's clock; the verifier reads the real
    // one. Minting an hour in the past yields an already-expired token at verify.
    $access = $this->travel(-3600)->seconds(fn () => issuer()->accessToken(ctx(1, 'fam')));

    expect(verifier()->verify($access['token']))->toBeNull();
});

it('tolerates a token expired within the leeway window', function () {
    // exp lands 3s in the past — inside the default 5s leeway — so it still verifies.
    $access = $this->travel(-((int) config('lukk.access_ttl') + 3))->seconds(fn () => issuer()->accessToken(ctx(1, 'fam')));

    expect(verifier()->verify($access['token'])?->sub)->toBe('1');
});

it('rejects a token that is not yet valid (nbf in the future)', function () {
    $access = $this->travel(3600)->seconds(fn () => issuer()->accessToken(ctx(1, 'fam')));

    expect(verifier()->verify($access['token']))->toBeNull();
});

it('embeds custom claims (e.g. roles) via tokenClaimsUsing', function () {
    // Through the ACTION, not the raw issuer: the hook is resolved by `StartSession` now, so that a
    // consumer callback never runs inside the refresh transaction's row lock. Asserting it against
    // the issuer would test a collaborator that no longer has the responsibility.
    Lukk::tokenClaimsUsing(fn ($userId) => ['roles' => ['admin', 'editor']]);

    $claims = claims(start()(7)->accessToken);

    expect($claims->roles)->toBe(['admin', 'editor'])
        ->and($claims->sub)->toBe('7');
});

it('does not let custom claims override the standard ones', function () {
    Lukk::tokenClaimsUsing(fn ($userId) => ['sub' => 'spoofed', 'roles' => ['x']]);

    $claims = claims(start()(7)->accessToken);

    expect($claims->sub)->toBe('7')
        ->and($claims->roles)->toBe(['x']);
});

it('ignores a claims hook handed straight to the issuer, which only stamps', function () {
    // The other half of the split: the issuer derives nothing. A custom `TokenIssuer` that forgets
    // this would silently drop custom claims, so pin that the raw issuer is now inert.
    Lukk::tokenClaimsUsing(fn ($userId) => ['roles' => ['admin']]);

    $claims = claims(issuer()->accessToken(ctx(7, 'fam'))['token']);

    expect((array) $claims)->not->toHaveKey('roles');
});

it('sets typ=at+jwt and alg=HS256 in the header', function () {
    [$header] = explode('.', issuer()->accessToken(ctx(1, 'fam'))['token']);
    $decoded = json_decode(base64_decode(strtr($header, '-_', '+/')), true);

    expect($decoded['typ'])->toBe('at+jwt')->and($decoded['alg'])->toBe('HS256');
});

it('rejects an access token that has no exp claim', function () {
    // A correctly-signed at+jwt with the right iss/aud but no exp must not be
    // treated as non-expiring.
    $token = JWT::encode([
        'iss' => config('lukk.issuer'),
        'aud' => config('lukk.audience'),
        'sub' => '1',
        'fid' => 'fam',
        'jti' => 'jti-no-exp',
        'iat' => time(),
        'nbf' => time(),
    ], config('lukk.secret'), 'HS256', head: ['typ' => 'at+jwt']);

    expect(verifier()->verify($token))->toBeNull();
});

it('rejects an access token whose sub is missing, empty, or not a string', function () {
    $claims = [
        'iss' => config('lukk.issuer'),
        'aud' => config('lukk.audience'),
        'jti' => 'j-sub',
        'iat' => time(),
        'nbf' => time(),
        'exp' => time() + 900,
    ];
    $secret = config('lukk.secret');
    $head = ['typ' => 'at+jwt'];

    $noSub = JWT::encode($claims, $secret, 'HS256', head: $head);
    $emptySub = JWT::encode(['sub' => ''] + $claims, $secret, 'HS256', head: $head);
    $arraySub = JWT::encode(['sub' => [1, 2]] + $claims, $secret, 'HS256', head: $head);

    expect(verifier()->verify($noSub))->toBeNull()
        ->and(verifier()->verify($emptySub))->toBeNull()
        ->and(verifier()->verify($arraySub))->toBeNull();
});

// No `lukk` config key is guaranteed at runtime. `mergeConfigDeep` early-returns when the
// application's config is CACHED (the production norm), so a key added in a later release is never
// backfilled; and the merge that does run backfills on `array_key_exists`, so a per-guard
// `'access_ttl' => env('LUKK_ADMIN_ACCESS_TTL')` with the variable unset survives it as an explicit
// null. Unguarded, `exp` is `$now + null` — EQUAL to `iat`, so every token that guard mints is
// already expired when it is handed out (login answers 200 and nothing it returns works), and
// `expires_in` serialises as null, which a client scheduling its refresh off it never recovers from.
it('takes an algorithm and a secret that arrive as non-strings, as a published config can hand them over', function () {
    // The three `(string)` casts in `KeyRing` are load-bearing, not hygiene: `firebase/php-jwt` types
    // both the algorithm and the key material as `string`, so an int or a `Stringable` reaching them
    // under `strict_types` is a TypeError — a 500 on every mint AND every verify, from a config that
    // merely round-tripped through something that lost its types. CLAUDE.md's rule is that no `lukk`
    // key is guaranteed to be what you expect at runtime.
    //
    // Pinned by hand because the mutation score cannot see it: these lines are covered by nearly every
    // test, so a mutant there runs the whole suite serially and is scored "detected" on a TIMEOUT
    // rather than on a failure — which is not detection at all.
    $secret = new class
    {
        public function __toString(): string
        {
            return str_repeat('k', 40);
        }
    };

    config(['lukk.secret' => $secret, 'lukk.algorithm' => new class
    {
        public function __toString(): string
        {
            return 'HS256';
        }
    }]);

    $access = app(TokenIssuer::class)->accessToken(ctx(1, 'fam'));

    expect(claims($access['token'])->sub)->toBe('1')
        ->and(verifier()->verify($access['token']))->not->toBeNull();
});

it('rejects a token declaring critical headers it does not understand', function () {
    // RFC 7515 §4.1.11 / RFC 7519 §7.2 step 10: a JWS whose `crit` names extensions the recipient does
    // not support MUST be rejected. lukk emits none, so anything carrying `crit` is a co-issuer
    // expressing a RESTRICTION — silently ignoring it is the inversion the parameter exists to prevent.
    $cfg = Lukk::guardConfig();
    $token = JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => '1', 'jti' => 'crit-token',
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt', 'crit' => ['exp-nonsense']]);

    expect(verifier()->verify($token))->toBeNull();
});

it('accepts both spellings RFC 9068 permits for the access-token type', function () {
    // §4 step 1: "Verify the `typ` header equals `at+jwt` or `application/at+jwt`." Only the short form
    // was accepted, so a co-issuer stamping the registered long form in a verify-only topology had
    // every token refused with no diagnostic. Media types compare case-insensitively (RFC 2045 §5.1).
    $cfg = Lukk::guardConfig();
    $mint = fn (string $typ) => JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => '1', 'jti' => 'typ-'.md5($typ),
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => $typ]);

    expect(verifier()->verify($mint('at+jwt')))->not->toBeNull()
        ->and(verifier()->verify($mint('application/at+jwt')))->not->toBeNull()
        ->and(verifier()->verify($mint('AT+JWT')))->not->toBeNull()
        // Still not a free-for-all: a challenge type is refused as a bearer.
        ->and(verifier()->verify($mint('2fa+challenge')))->toBeNull()
        ->and(verifier()->verify($mint('JWT')))->toBeNull();
});

it('stops validating nothing when the issuer is absent — it refuses instead', function (Closure $break) {
    // `null !== null` is false, so with no configured issuer this check silently stopped being one.
    // `ChallengeToken` already failed closed here; this is the half that did not.
    $cfg = Lukk::guardConfig();
    $token = JWT::encode([
        'aud' => $cfg['audience'], 'sub' => '1', 'jti' => 'no-iss',
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);

    $break();

    expect(verifier()->verify($token))->toBeNull();
})->with([
    'null (a per-guard env that is not set)' => [fn () => config()->set('lukk.issuer', null)],
    'absent (a config cached before the key existed)' => [fn () => config()->set('lukk', Arr::except(config('lukk'), ['issuer']))],
]);

it('mints a full-lifetime access token when access_ttl is unusable', function (Closure $break) {
    $break();

    $access = app(TokenIssuer::class)->accessToken(ctx(1, 'fam'));
    $claims = claims($access['token']);

    expect($access['expires_in'])->toBe(900)
        ->and((int) $claims->exp - (int) $claims->iat)->toBe(900);
})->with([
    'null (a per-guard env that is not set)' => [fn () => config()->set('lukk.access_ttl', null)],
    'absent (a config cached before the key existed)' => [fn () => config()->set('lukk', Arr::except(config('lukk'), ['access_ttl']))],
]);

/** Mint a token with exactly these claims, signed by this guard's key. */
function signedClaims(array $claims): string
{
    $cfg = Lukk::guardConfig();

    return JWT::encode(array_merge([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => '1',
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $claims), $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);
}

it('never matches an empty audience entry against an empty one the token presents', function () {
    // A blank `LUKK_AUDIENCE=` line on both sides would otherwise intersect on '' and admit a token
    // minted for nobody — the audience check is what isolates one guard's tokens from another's.
    config(['lukk.audience' => ['https://api.example.com', '']]);

    expect(verifier()->verify(signedClaims(['aud' => ['']])))->toBeNull()
        ->and(verifier()->verify(signedClaims(['aud' => ['https://api.example.com']])))->not->toBeNull();
});

it('honours the configured leeway, and five seconds when it is unset', function () {
    // The clock skew a verifier tolerates. Read as 0 and a token minted a second ago by a peer whose
    // clock runs slow is refused; read as unbounded and an expired token lives on. Asserted on the
    // value handed to the library, because the library compares against real `time()` — a test that
    // tried to straddle one second of it would flake.
    config(['lukk.leeway' => 120]);
    verifier()->verify('not-a-token');
    expect(JWT::$leeway)->toBe(120);

    // ...and it is the value that decides: a token 30 seconds past `exp` still verifies under it.
    expect(verifier()->verify(signedClaims(['exp' => time() - 30])))->not->toBeNull();

    $lukk = (array) config('lukk');
    unset($lukk['leeway']);
    config()->set('lukk', $lukk);
    verifier()->verify('not-a-token');

    expect(JWT::$leeway)->toBe(5)
        ->and(verifier()->verify(signedClaims(['exp' => time() - 30])))->toBeNull();
});

it('reads a jti or fid another issuer encoded as a number', function () {
    // Both reach the denylist as strings; a JSON number there was a TypeError on every request.
    expect(verifier()->verify(signedClaims(['jti' => 42, 'fid' => 7])))->not->toBeNull();
});
