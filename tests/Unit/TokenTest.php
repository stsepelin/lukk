<?php

declare(strict_types=1);
use Firebase\JWT\JWT;
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
    $access = issuer()->accessToken(123, 'fam-1');
    $claims = verifier()->verify($access['token']);

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
    $access = app(TokenIssuer::class)->accessToken(1, 'fam');
    config(['lukk.audience' => 'https://api.example.com']);

    expect(verifier()->verify($access['token']))->toBeNull();
});

it('mints a multi-audience array and accepts it at each listed service', function () {
    // One issuer mints a token intended for two services.
    $config = config('lukk');
    $config['audience'] = ['https://api.example.com', 'https://billing.example.com'];

    $token = (new FirebaseTokenIssuer($config))->accessToken(1, 'fam')['token'];

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
    $access = app(TokenIssuer::class)->accessToken(1, 'fam');
    config(['lukk.issuer' => 'https://api.example.com']);

    expect(verifier()->verify($access['token']))->toBeNull();
});

it('rejects a token whose jti is denylisted', function () {
    $access = issuer()->accessToken(5, 'fam-x');
    expect(verifier()->verify($access['token']))->not->toBeNull();

    app(Denylist::class)->revokeJti($access['jti'], 900);

    expect(verifier()->verify($access['token']))->toBeNull();
});

it('rejects an access token whose exp has passed', function () {
    // The issuer stamps exp/nbf from Carbon's clock; the verifier reads the real
    // one. Minting an hour in the past yields an already-expired token at verify.
    $access = $this->travel(-3600)->seconds(fn () => issuer()->accessToken(1, 'fam'));

    expect(verifier()->verify($access['token']))->toBeNull();
});

it('tolerates a token expired within the leeway window', function () {
    // exp lands 3s in the past — inside the default 5s leeway — so it still verifies.
    $access = $this->travel(-((int) config('lukk.access_ttl') + 3))->seconds(fn () => issuer()->accessToken(1, 'fam'));

    expect(verifier()->verify($access['token'])?->sub)->toBe('1');
});

it('rejects a token that is not yet valid (nbf in the future)', function () {
    $access = $this->travel(3600)->seconds(fn () => issuer()->accessToken(1, 'fam'));

    expect(verifier()->verify($access['token']))->toBeNull();
});

it('embeds custom claims (e.g. roles) via tokenClaimsUsing', function () {
    Lukk::tokenClaimsUsing(fn ($userId) => ['roles' => ['admin', 'editor']]);

    $claims = verifier()->verify(issuer()->accessToken(7, 'fam')['token']);

    expect($claims->roles)->toBe(['admin', 'editor'])
        ->and($claims->sub)->toBe('7');
});

it('does not let custom claims override the standard ones', function () {
    Lukk::tokenClaimsUsing(fn ($userId) => ['sub' => 'spoofed', 'roles' => ['x']]);

    $claims = verifier()->verify(issuer()->accessToken(7, 'fam')['token']);

    expect($claims->sub)->toBe('7')
        ->and($claims->roles)->toBe(['x']);
});

it('sets typ=at+jwt and alg=HS256 in the header', function () {
    [$header] = explode('.', issuer()->accessToken(1, 'fam')['token']);
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
