<?php

declare(strict_types=1);

function useAsymmetric(array $keypair, string $kid = 'k1'): void
{
    config([
        'lukk.algorithm' => 'RS256',
        'lukk.keys' => ['active' => $kid, 'private' => $keypair['private'], 'passphrase' => null, 'public' => [$kid => $keypair['public']]],
    ]);
}

/**
 * Publish `$private` as the only key under `$algorithm` and report its JWK curve plus the raw byte
 * length of each coordinate — the two things RFC 7518 §6.2.1.2 pins down.
 *
 * @return array{crv: string, x: int, y: int}
 */
function ecJwkCoordinates(string $private, string $algorithm): array
{
    $key = openssl_pkey_get_private($private);
    assert($key !== false);
    $details = openssl_pkey_get_details($key);
    assert($details !== false);

    config([
        'lukk.algorithm' => $algorithm,
        'lukk.keys' => ['active' => 'ec1', 'private' => $private, 'passphrase' => null, 'public' => ['ec1' => $details['key']]],
    ]);

    // Assert the key is in the set before reading it: an omitted curve should read as "0 keys
    // published", not as a null coordinate three lines further down.
    $jwk = test()->getJson('/auth/jwks')->assertOk()->assertJsonCount(1, 'keys')->json('keys.0');
    $decode = fn (string $s): string => (string) base64_decode(strtr($s, '-_', '+/').str_repeat('=', (4 - strlen($s) % 4) % 4));

    return ['crv' => $jwk['crv'], 'x' => strlen($decode($jwk['x'])), 'y' => strlen($decode($jwk['y']))];
}

it('publishes the public keys at the JWKS endpoint', function () {
    useAsymmetric(rsaKeypair(), 'k1');

    $this->getJson('/auth/jwks')
        ->assertOk()
        ->assertJsonStructure(['keys' => [['kid', 'kty', 'use', 'alg', 'n', 'e']]])
        ->assertJsonPath('keys.0.kid', 'k1')
        ->assertJsonPath('keys.0.use', 'sig');
});

it('marks the JWKS response publicly cacheable', function () {
    useAsymmetric(rsaKeypair());

    $response = $this->getJson('/auth/jwks');

    expect($response->headers->getCacheControlDirective('public'))->toBeTrue()
        ->and($response->headers->getCacheControlDirective('max-age'))->toBe('3600');
});

it('serves an empty JWK set under a symmetric algorithm', function () {
    // The suite's default algorithm is HS256 — no public keys to publish.
    $this->getJson('/auth/jwks')->assertOk()->assertExactJson(['keys' => []]);
});

it('left-pads EC JWK coordinates to the curve field size (RFC 7518 §6.2.1.2)', function () {
    // ES256 key whose `y` coordinate is 31 raw bytes (leading zero). Without padding the
    // published JWK would carry a 31-byte `y`, which strict JWKS consumers reject.
    $private = "-----BEGIN PRIVATE KEY-----\n"
        ."MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGiJyeOMghi117QqZ\n"
        ."vZgXSH/NY5PkFE/aBr/L7h1jMC2hRANCAAS7NWz7LZyO8lYjoB6JN78izpITd/pS\n"
        ."X3v6f62UAyr+nQBTubRnb8cZA6Hn9gZbUOH+Ahlwo+978+SVycBXvdXH\n"
        ."-----END PRIVATE KEY-----\n";
    $public = openssl_pkey_get_details(openssl_pkey_get_private($private))['key'];

    config([
        'lukk.algorithm' => 'ES256',
        'lukk.keys' => ['active' => 'ec1', 'private' => $private, 'passphrase' => null, 'public' => ['ec1' => $public]],
    ]);

    $jwk = $this->getJson('/auth/jwks')->assertOk()->json('keys.0');
    $decode = fn (string $s): string => (string) base64_decode(strtr($s, '-_', '+/').str_repeat('=', (4 - strlen($s) % 4) % 4));

    expect($jwk['kty'])->toBe('EC')
        ->and($jwk['crv'])->toBe('P-256')
        ->and(strlen($decode($jwk['x'])))->toBe(32)
        ->and(strlen($decode($jwk['y'])))->toBe(32); // padded up from 31
});

it('left-pads P-384 coordinates to the 48-byte field size', function () {
    // ES384 key whose `x` coordinate is 47 raw bytes. The key is PINNED rather than generated: a
    // random P-384 key loses a leading zero byte roughly 1 time in 256, so a generated one would
    // assert nothing on 255 runs out of 256 and then fail in CI on the one that matters.
    $private = "-----BEGIN PRIVATE KEY-----\n"
        ."MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDA+5M4VPh5c9rcqK2hA\n"
        ."Jx4c+/kvFivAhsEDhxTrucvDv4bcL57MYOKwtTuvClQY9iChZANiAAQACQ/oUP4x\n"
        ."nTMvFUs2CaIRlJv/6xWCxhCv2eKVvNMUdmhAIQEVvXywGRt0vQQ6IsG3Tu1vCM+w\n"
        ."xiUNFcVbwz2JGCaM0hIchG6bLrQeTW5nvjZTNuK/FIPqwOVNSUuBbR4=\n"
        ."-----END PRIVATE KEY-----\n";

    expect(ecJwkCoordinates($private, 'ES384'))->toBe(['crv' => 'P-384', 'x' => 48, 'y' => 48]); // `x` padded up from 47
});

it('left-pads P-521 coordinates to the 66-byte field size', function () {
    // ES512 key whose `y` coordinate is 65 raw bytes. P-521 is the curve where this bites hardest:
    // the field is 521 bits, so the top octet of a coordinate is 0x00 or 0x01 and openssl strips it
    // on about half of all keys — the "1 in 256" of the other curves becomes a coin flip.
    $private = "-----BEGIN PRIVATE KEY-----\n"
        ."MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB0TMx1NjNiqN2OSm8\n"
        ."okd1IFqXOYhdgRCUwnB9SjviB48hYB7DXFbuL+Qqq+aeH2hBYX862YiJXbkG4M5d\n"
        ."P2s2gxyhgYkDgYYABAGWxG2onse+M4LPw5F+KdzHpuZSdj37QL840Gdz6MRnOwLP\n"
        ."+amWWpXojuLSBvBDzsiBynBZtnqc5HKOnqfF5yvlmwDbcqH9G9QyDCk601UD9T7x\n"
        ."bHv0+hX6+cN+3W1z3FHBf8dJ5WVocQAHXZJLiuxRlrHE6QGnVQRJXwN+rLUHOyrl\n"
        ."UA==\n"
        ."-----END PRIVATE KEY-----\n";

    expect(ecJwkCoordinates($private, 'ES512'))->toBe(['crv' => 'P-521', 'x' => 66, 'y' => 66]); // `y` padded up from 65
});

it('omits an EC key on a curve whose field length it does not know', function () {
    // RFC 7518 §6.2.1.2 requires each coordinate to be "the full size of a coordinate for the curve".
    // For an unmapped curve there is no known size, and the padding quietly became the identity
    // function — publishing the very short coordinate the rule forbids, on roughly 1 key in 200.
    // `ES256K` reaches here: php-jwt supports it and nothing validates `lukk.algorithm` against an
    // allowlist. A JWK we cannot state correctly is one we do not publish.
    $res = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp256k1']);
    assert($res !== false);
    openssl_pkey_export($res, $private);
    $details = openssl_pkey_get_details($res);
    assert($details !== false);

    useAsymmetric(['private' => (string) $private, 'public' => (string) $details['key']], 'k1');
    config(['lukk.algorithm' => 'ES256K']);

    $this->getJson('/auth/jwks')->assertOk()->assertExactJson(['keys' => []]);
});

it('omits a key whose type does not match the configured algorithm', function () {
    // `kty` used to be chosen from the ALGORITHM, so an RSA key under ES256 indexed the EC details
    // of an RSA key and published `{"kty":"EC","crv":"","x":"","y":""}` — a structurally invalid JWK
    // that a strict consumer chokes on. Signing is already broken at that point; say so loudly.
    useAsymmetric(rsaKeypair(), 'k1');
    config(['lukk.algorithm' => 'ES256']);

    $this->getJson('/auth/jwks')->assertOk()->assertExactJson(['keys' => []]);
});

it('omits an EC key under an RSA algorithm', function () {
    // The mirror of the case above, and the half that a plain `kty === EC` test misses: an EC key
    // left in `keys.public` while `lukk.algorithm` is RS256. Publishing it would advertise `"alg":
    // "RS256"` over an EC public key — a signature that key can never produce.
    useAsymmetric(ecKeypair(), 'k1');

    $this->getJson('/auth/jwks')->assertOk()->assertExactJson(['keys' => []]);
});
