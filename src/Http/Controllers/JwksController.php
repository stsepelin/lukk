<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Lukk\Lukk;
use Lukk\Tokens\Jwt\KeyRing;

/**
 * Publishes the issuer's public signing keys as a JWK Set (RFC 7517) so an
 * independent service can verify tokens without sharing a secret. Public and
 * cacheable — it exposes only public keys, never the signing secret or private
 * key — and empty under a symmetric algorithm (HS*). Resolves the CURRENT guard's
 * keys, so each guard's `/jwks` reflects its own signing material.
 */
class JwksController
{
    public function __invoke(): JsonResponse
    {
        $jwks = (new KeyRing(Lukk::guardConfig()))->jwks();

        // RFC 7517 §8.5.1 registers `application/jwk-set+json` for a JWK Set; it is still JSON to any client
        // that parses the body, and says what the document is to one that dispatches on the type.
        return response()->json($jwks)->header('Content-Type', 'application/jwk-set+json')->setPublic()->setMaxAge(3600);
    }
}
