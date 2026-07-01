<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Lukk\Contracts\Denylist;
use Lukk\Tokens\Jwt\FirebaseTokenIssuer;
use Lukk\Tokens\Jwt\FirebaseTokenVerifier;
use Lukk\Tokens\Jwt\KeyRing;

function asymConfig(string $alg, array $public, mixed $private, string $activeKid, ?string $passphrase = null): array
{
    return [
        'algorithm' => $alg,
        'secret' => null,
        'issuer' => 'https://issuer.test',
        'audience' => 'https://api.test',
        'access_ttl' => 900,
        'leeway' => 5,
        'keys' => ['active' => $activeKid, 'private' => $private, 'passphrase' => $passphrase, 'public' => $public],
    ];
}

function asymVerifier(array $config): FirebaseTokenVerifier
{
    return new FirebaseTokenVerifier($config, app(Denylist::class));
}

it('issues and verifies an RS256 access token', function () {
    $kp = rsaKeypair();
    $config = asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], 'k1');

    $token = (new FirebaseTokenIssuer($config))->accessToken(42, 'fam-1')['token'];
    $claims = asymVerifier($config)->verify($token);

    expect($claims)->not->toBeNull()
        ->and($claims->sub)->toBe('42')
        ->and($claims->fid)->toBe('fam-1');
});

it('issues and verifies an ES256 access token', function () {
    $kp = ecKeypair();
    $config = asymConfig('ES256', ['k1' => $kp['public']], $kp['private'], 'k1');

    $token = (new FirebaseTokenIssuer($config))->accessToken(7, 'fam')['token'];

    expect(asymVerifier($config)->verify($token))->not->toBeNull();
});

it('rejects an HS256 token forged with the public key as the HMAC secret (alg confusion)', function () {
    $kp = rsaKeypair();
    $config = asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], 'k1');

    // The classic downgrade: sign HS256 using the RS256 *public* key bytes as the
    // shared secret. A verifier that doesn't pin the algorithm would accept it.
    $forged = JWT::encode(
        ['iss' => 'https://issuer.test', 'aud' => 'https://api.test', 'sub' => '1', 'exp' => time() + 900],
        $kp['public'], 'HS256', keyId: 'k1', head: ['typ' => 'at+jwt'],
    );

    expect(asymVerifier($config)->verify($forged))->toBeNull();
});

it('rejects a token signed by a key that is not in the verification set', function () {
    $mint = rsaKeypair();
    $other = rsaKeypair();
    // Issue under one key, but the verifier only knows a different key for that kid.
    $token = (new FirebaseTokenIssuer(asymConfig('RS256', ['k1' => $mint['public']], $mint['private'], 'k1')))
        ->accessToken(1, 'fam')['token'];

    expect(asymVerifier(asymConfig('RS256', ['k1' => $other['public']], $other['private'], 'k1'))->verify($token))->toBeNull();
});

it('keeps a retired key valid during the rotation overlap, then rejects it once removed', function () {
    $old = rsaKeypair();
    $new = rsaKeypair();

    $oldToken = (new FirebaseTokenIssuer(asymConfig('RS256', ['old' => $old['public']], $old['private'], 'old')))
        ->accessToken(7, 'fam')['token'];

    // Overlap: new key active and signing, old public key still listed.
    $overlap = asymConfig('RS256', ['new' => $new['public'], 'old' => $old['public']], $new['private'], 'new');
    expect(asymVerifier($overlap)->verify($oldToken))->not->toBeNull();

    // Retired: old key dropped from the set — its tokens no longer verify.
    $retired = asymConfig('RS256', ['new' => $new['public']], $new['private'], 'new');
    expect(asymVerifier($retired)->verify($oldToken))->toBeNull();
});

it('loads keys from inline PEM and from file paths interchangeably', function () {
    $kp = rsaKeypair();
    $dir = sys_get_temp_dir().'/lukk-keys-'.getmypid();
    @mkdir($dir);
    file_put_contents("$dir/priv.pem", $kp['private']);
    file_put_contents("$dir/pub.pem", $kp['public']);

    // private via a bare path, public via an "@path" reference.
    $config = asymConfig('RS256', ['k1' => "@$dir/pub.pem"], "$dir/priv.pem", 'k1');
    $token = (new FirebaseTokenIssuer($config))->accessToken(3, 'fam')['token'];

    expect(asymVerifier($config)->verify($token))->not->toBeNull();

    @unlink("$dir/priv.pem");
    @unlink("$dir/pub.pem");
    @rmdir($dir);
});

it('decrypts a passphrase-protected private key', function () {
    $kp = rsaKeypair('s3cr3t-pass');
    $config = asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], 'k1', 's3cr3t-pass');

    $token = (new FirebaseTokenIssuer($config))->accessToken(9, 'fam')['token'];

    expect(asymVerifier($config)->verify($token))->not->toBeNull();
});

it('refuses to sign when the active kid is empty or absent from the public set', function () {
    $kp = rsaKeypair();

    // Empty active kid — would mint tokens with no kid that nothing can verify.
    expect(fn () => (new KeyRing(asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], '')))->signingKey())
        ->toThrow(InvalidArgumentException::class);

    // Active kid not present in the public map — same silent-outage hazard.
    expect(fn () => (new KeyRing(asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], 'k2')))->signingKey())
        ->toThrow(InvalidArgumentException::class);
});

it('skips blank and unreadable public-key entries', function () {
    $kp = rsaKeypair();
    $ring = new KeyRing(asymConfig(
        'RS256',
        ['k1' => $kp['public'], 'blank' => '', 'missing' => '@/no/such/key.pem'],
        $kp['private'],
        'k1',
    ));

    expect(array_keys($ring->publicKeys()))->toBe(['k1']);
});

it('memoizes verification keys so repeated verifies reuse one Key set', function () {
    $kp = rsaKeypair();
    $ring = new KeyRing(asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], 'k1'));

    // Same instances on the second call → no per-verify Key alloc / PEM re-read.
    expect($ring->verificationKeys())->toBe($ring->verificationKeys())
        ->and($ring->publicKeys())->toBe($ring->publicKeys());
});

it('memoizes the symmetric verification key', function () {
    $ring = new KeyRing(['algorithm' => 'HS256', 'secret' => str_repeat('a', 32)]);

    expect($ring->verificationKeys())->toBe($ring->verificationKeys());
});

it('throws a clear error when the private-key passphrase is wrong', function () {
    $kp = rsaKeypair('correct-pass');
    $config = asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], 'k1', 'wrong-pass');

    expect(fn () => (new FirebaseTokenIssuer($config))->accessToken(1, 'fam'))
        ->toThrow(InvalidArgumentException::class);
});

it('builds an RSA JWK set and skips unparseable public keys', function () {
    $kp = rsaKeypair();
    $ring = new KeyRing(asymConfig('RS256', [
        'good' => $kp['public'],
        'bad' => "-----BEGIN PUBLIC KEY-----\nnot-a-real-key\n-----END PUBLIC KEY-----",
    ], $kp['private'], 'good'));

    $jwks = $ring->jwks();

    expect($jwks['keys'])->toHaveCount(1)
        ->and($jwks['keys'][0])->toMatchArray(['kid' => 'good', 'use' => 'sig', 'alg' => 'RS256', 'kty' => 'RSA'])
        ->and($jwks['keys'][0])->toHaveKeys(['n', 'e']);
});

it('builds an EC JWK for ES256', function () {
    $kp = ecKeypair();

    $jwks = (new KeyRing(asymConfig('ES256', ['k1' => $kp['public']], $kp['private'], 'k1')))->jwks();

    expect($jwks['keys'][0])->toMatchArray(['kty' => 'EC', 'crv' => 'P-256'])
        ->and($jwks['keys'][0])->toHaveKeys(['x', 'y']);
});
