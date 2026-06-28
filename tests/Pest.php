<?php

declare(strict_types=1);

use Lukk\Actions\RevokeAllSessions;
use Lukk\Actions\RevokeSession;
use Lukk\Actions\RotateRefreshToken;
use Lukk\Actions\StartSession;
use Lukk\Contracts\TokenIssuer;
use Lukk\Contracts\TokenVerifier;
use Lukk\Tests\TestCase;

uses(TestCase::class)->in('Unit', 'Feature');

function start(): StartSession
{
    return app(StartSession::class);
}
function rotate(): RotateRefreshToken
{
    return app(RotateRefreshToken::class);
}
function revokeSession(): RevokeSession
{
    return app(RevokeSession::class);
}
function revokeAll(): RevokeAllSessions
{
    return app(RevokeAllSessions::class);
}
function verifier(): TokenVerifier
{
    return app(TokenVerifier::class);
}
function issuer(): TokenIssuer
{
    return app(TokenIssuer::class);
}

/** Earn a step-up confirmation header for the given access token. */
function confirmedHeaders(string $access): array
{
    $token = test()->withToken($access)
        ->postJson('/auth/confirm-password', ['password' => 'password'])
        ->json('confirmation_token');

    return ['X-Lukk-Confirmation' => $token];
}

/** @return array{private:string, public:string} a fresh RSA-2048 keypair (PEM). */
function rsaKeypair(?string $passphrase = null): array
{
    $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($res, $private, $passphrase);

    return ['private' => $private, 'public' => openssl_pkey_get_details($res)['key']];
}

/** @return array{private:string, public:string} a fresh EC P-256 keypair (PEM). */
function ecKeypair(): array
{
    $res = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    openssl_pkey_export($res, $private);

    return ['private' => $private, 'public' => openssl_pkey_get_details($res)['key']];
}
