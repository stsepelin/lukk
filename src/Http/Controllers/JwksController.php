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

        return response()->json($jwks)->setPublic()->setMaxAge(3600);
    }
}
