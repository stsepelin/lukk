<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Lukk\Contracts\Denylist;
use Lukk\Tokens\Jwt\FirebaseTokenIssuer;
use Lukk\Tokens\Jwt\FirebaseTokenVerifier;
use Lukk\Tokens\Jwt\KeyRing;

/** A path that stats as a regular file and then refuses to open — a key file with the wrong owner. */
class UnreadableKeyFile
{
    /** @var resource|null */
    public $context;

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        return false;
    }

    /** @return array{mode: int} */
    public function url_stat(string $path, int $flags): array
    {
        return ['mode' => 0100000]; // S_IFREG, no permission bits.
    }
}

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

    $token = (new FirebaseTokenIssuer($config))->accessToken(ctx(42, 'fam-1'))['token'];
    $claims = asymVerifier($config)->verify($token);

    expect($claims)->not->toBeNull()
        ->and($claims->sub)->toBe('42')
        ->and($claims->fid)->toBe('fam-1');
});

it('issues and verifies an ES256 access token', function () {
    $kp = ecKeypair();
    $config = asymConfig('ES256', ['k1' => $kp['public']], $kp['private'], 'k1');

    $token = (new FirebaseTokenIssuer($config))->accessToken(ctx(7, 'fam'))['token'];

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
        ->accessToken(ctx(1, 'fam'))['token'];

    expect(asymVerifier(asymConfig('RS256', ['k1' => $other['public']], $other['private'], 'k1'))->verify($token))->toBeNull();
});

it('keeps a retired key valid during the rotation overlap, then rejects it once removed', function () {
    $old = rsaKeypair();
    $new = rsaKeypair();

    $oldToken = (new FirebaseTokenIssuer(asymConfig('RS256', ['old' => $old['public']], $old['private'], 'old')))
        ->accessToken(ctx(7, 'fam'))['token'];

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
    $token = (new FirebaseTokenIssuer($config))->accessToken(ctx(3, 'fam'))['token'];

    expect(asymVerifier($config)->verify($token))->not->toBeNull();

    @unlink("$dir/priv.pem");
    @unlink("$dir/pub.pem");
    @rmdir($dir);
});

it('decrypts a passphrase-protected private key', function () {
    $kp = rsaKeypair('s3cr3t-pass');
    $config = asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], 'k1', 's3cr3t-pass');

    $token = (new FirebaseTokenIssuer($config))->accessToken(ctx(9, 'fam'))['token'];

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

it('names the offending value when there is no active kid at all', function () {
    // An absent `keys.active` — an unset `env('LUKK_ACTIVE_KID')` — reads as empty, and the message
    // has to say which kid lukk went looking for: it is the operator's only clue as to whether the
    // key is misnamed or simply missing.
    $kp = rsaKeypair();
    $config = asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], 'k1');
    unset($config['keys']['active']);

    expect(fn () => (new KeyRing($config))->signingKey())
        ->toThrow(InvalidArgumentException::class, "lukk.keys.active ('') must be non-empty");
});

it('refuses an empty active kid even when the public set holds an entry under the empty name', function () {
    // `'public' => [env('LUKK_KID') => $pem]` with that variable unset registers the key under the
    // EMPTY name, and `'active' => env('LUKK_ACTIVE_KID')` reads empty too. The pair then matches,
    // so a presence check alone would sign and publish `"kid":""`. An unset active kid is unset —
    // not the name of a key.
    $kp = rsaKeypair();

    expect(fn () => (new KeyRing(asymConfig('RS256', ['' => $kp['public']], $kp['private'], '')))->signingKey())
        ->toThrow(InvalidArgumentException::class);
});

it('stamps a numeric kid as a string in both the signing header and the JWK set', function () {
    // PHP turns a numeric array key into an int, so `'public' => [2024 => $pem]` invites the matching
    // `'active' => 2024`. But `kid` is "a case-sensitive string" in RFC 7515 §4.1.4 and RFC 7517
    // §4.5 alike: uncast it would be stamped and published as the JSON number 2024, which a consumer
    // matching a header kid against a JWKS kid by string never lines up with.
    $kp = rsaKeypair();
    $config = asymConfig('RS256', [2024 => $kp['public']], $kp['private'], '2024');
    $config['keys']['active'] = 2024; // the int the map key silently became; the helper types it string.
    $ring = new KeyRing($config);

    expect($ring->signingKey()['kid'])->toBe('2024')
        ->and($ring->jwks()['keys'][0]['kid'])->toBe('2024');
});

it('skips blank, unset and unreadable public-key entries', function () {
    // `null` is what an unset `env('LUKK_PUBLIC_KEY_2')` puts in the map — a kid that is configured
    // in name only. It is skipped like the others, not handed on to the string functions below it.
    $kp = rsaKeypair();
    $ring = new KeyRing(asymConfig(
        'RS256',
        ['k1' => $kp['public'], 'blank' => '', 'unset' => null, 'missing' => '@/no/such/key.pem'],
        $kp['private'],
        'k1',
    ));

    expect(array_keys($ring->publicKeys()))->toBe(['k1']);
});

it('skips a public key that stats as a file but cannot be read', function () {
    // The classic secrets-mount failure: the path is there, the ownership is wrong. `is_file()` says
    // yes, so the guard admits it, and the read then fails. Both halves have to be handled for this to
    // be the skip the method promises: the `(string)` cast turns `false` into `''` rather than a
    // TypeError out of a `: string` method, and the `@` stops the E_WARNING that Laravel's error
    // handler would otherwise raise as an ErrorException — a 500 on EVERY verify because one
    // non-active kid is unreadable. Nothing is suppressed at THIS call site: if either half regresses,
    // this test fails rather than quietly tolerating it.
    if (! in_array('lukk-unreadable', stream_get_wrappers(), true)) {
        stream_wrapper_register('lukk-unreadable', UnreadableKeyFile::class);
    }

    $kp = rsaKeypair();
    $ring = new KeyRing(asymConfig(
        'RS256',
        ['k1' => $kp['public'], 'denied' => '@lukk-unreadable://key.pem'],
        $kp['private'],
        'k1',
    ));

    expect(array_keys($ring->publicKeys()))->toBe(['k1']);
});

it('tolerates a keys.public written as a bare PEM instead of a kid map', function () {
    // `'public' => $pem`, the kid map forgotten. It is a misconfiguration either way, but iterating a
    // string is a PHP warning — an ErrorException under Laravel's handler, so a 500 on every verify —
    // where reading it as a one-entry set still verifies the tokens that same config signs.
    $kp = rsaKeypair();
    $config = asymConfig('RS256', [], $kp['private'], '0');
    $config['keys']['public'] = $kp['public'];

    expect(array_values((new KeyRing($config))->publicKeys()))->toBe([$kp['public']]);
});

it('memoizes verification keys so repeated verifies reuse one Key set', function () {
    $kp = rsaKeypair();
    $ring = new KeyRing(asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], 'k1'));

    // Same instances on the second call → no per-verify Key alloc / PEM re-read.
    expect($ring->verificationKeys())->toBe($ring->verificationKeys())
        ->and($ring->publicKeys())->toBe($ring->publicKeys());
});

it('reads the public keys from disk once, not on every verify', function () {
    // The same reason the signing key is memoized, on the hotter path: every verified request asks
    // for the verification set, and unmemoized each one re-runs `is_file()` + `file_get_contents()`
    // per configured kid. Config is immutable for the life of the process; the PEMs behind it are too.
    $kp = rsaKeypair();
    $path = tempnam(sys_get_temp_dir(), 'lukk-pub').'.pem';
    file_put_contents($path, $kp['public']);

    $ring = new KeyRing(asymConfig('RS256', ['k1' => '@'.$path], $kp['private'], 'k1'));
    expect(array_keys($ring->publicKeys()))->toBe(['k1']);

    // Delete the file: a second call that still knows the key proves it was not re-read from disk.
    unlink($path);

    expect(array_keys($ring->publicKeys()))->toBe(['k1'])
        ->and($ring->jwks()['keys'])->toHaveCount(1);
});

it('memoizes the symmetric verification key', function () {
    $ring = new KeyRing(['algorithm' => 'HS256', 'secret' => str_repeat('a', 32)]);

    expect($ring->verificationKeys())->toBe($ring->verificationKeys());
});

it('throws a clear error when the private-key passphrase is wrong', function () {
    $kp = rsaKeypair('correct-pass');
    $config = asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], 'k1', 'wrong-pass');

    expect(fn () => (new FirebaseTokenIssuer($config))->accessToken(ctx(1, 'fam')))
        ->toThrow(InvalidArgumentException::class);
});

it('treats a missing passphrase and an empty one alike, handing the signer the PEM itself', function (?string $passphrase) {
    // `'passphrase' => env('LUKK_KEY_PASSPHRASE')` reads as null on an install that has none, and as
    // `''` once someone writes the variable out empty. Both mean "there is nothing to decrypt", not
    // "decrypt with the empty passphrase" — openssl accepts `''` against an unencrypted key, so
    // taking that branch anyway would hand a decrypt failure, blaming a passphrase no one set, to
    // the first install whose key IS encrypted.
    $kp = rsaKeypair();
    $ring = new KeyRing(asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], 'k1', $passphrase));

    expect($ring->signingKey()['key'])->toBe($kp['private']);
})->with([null, '']);

it('accepts a passphrase written as a number in config', function () {
    // An all-digit passphrase is an int in a PHP config array, and `openssl_pkey_get_private()` takes
    // `?string`: under `strict_types` an uncast int is a TypeError, i.e. every mint dies on a
    // passphrase that is perfectly correct.
    $kp = rsaKeypair('12345');
    $config = asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], 'k1');
    $config['keys']['passphrase'] = 12345;

    expect((new KeyRing($config))->signingKey()['key'])->toBeInstanceOf(OpenSSLAsymmetricKey::class);
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

it('encodes JWK members as unpadded base64url', function () {
    // RFC 7515 App. C: the encoding here carries no `=` padding. A 2048-bit modulus is 256 bytes,
    // which always base64s with two of them, so a consumer that decodes members strictly — or
    // compares two JWKs byte for byte — chokes on every RSA key lukk publishes.
    $kp = rsaKeypair();

    $jwk = (new KeyRing(asymConfig('RS256', ['k1' => $kp['public']], $kp['private'], 'k1')))->jwks()['keys'][0];

    expect($jwk['n'])->not->toContain('=');
});

it('builds an EC JWK for ES256', function () {
    $kp = ecKeypair();

    $jwks = (new KeyRing(asymConfig('ES256', ['k1' => $kp['public']], $kp['private'], 'k1')))->jwks();

    expect($jwks['keys'][0])->toMatchArray(['kty' => 'EC', 'crv' => 'P-256'])
        ->and($jwks['keys'][0])->toHaveKeys(['x', 'y']);
});

it('reads and decrypts the signing key once, not on every mint', function () {
    // Signing happens inside the refresh transaction's row lock. Unmemoized, this ran `is_file()`,
    // `file_get_contents()` and — with a passphrase — `openssl_pkey_get_private()` on EVERY mint: a
    // disk read and an asymmetric key decrypt while holding `SELECT … FOR UPDATE`, which is exactly
    // what moving the consumer callbacks out of that transaction was meant to prevent.
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    openssl_pkey_export($key, $pem, 'sekrit');
    $path = tempnam(sys_get_temp_dir(), 'lukk-key').'.pem';
    file_put_contents($path, $pem);

    $config = asymConfig('ES256', ['k1' => openssl_pkey_get_details($key)['key']], '@'.$path, 'k1', 'sekrit');

    $issuer = new FirebaseTokenIssuer($config);
    expect($issuer->accessToken(ctx(1, 'fam'))['token'])->toBeString();

    // Delete the file: a second mint that still works proves the key was not re-read from disk.
    unlink($path);

    expect($issuer->accessToken(ctx(1, 'fam'))['token'])->toBeString();
});
