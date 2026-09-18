<?php

declare(strict_types=1);

function useAsymmetric(array $keypair, string $kid = 'k1'): void
{
    config([
        'lukk.algorithm' => 'RS256',
        'lukk.keys' => ['active' => $kid, 'private' => $keypair['private'], 'passphrase' => null, 'public' => [$kid => $keypair['public']]],
    ]);
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
