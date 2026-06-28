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
