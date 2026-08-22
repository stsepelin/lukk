<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Testing\PendingCommand;
use Lukk\Actions\RevokeAllSessions;
use Lukk\Actions\RevokeSession;
use Lukk\Actions\RotateRefreshToken;
use Lukk\Actions\StartSession;
use Lukk\Contracts\HasTokenAbilities;
use Lukk\Contracts\TokenIssuer;
use Lukk\Contracts\TokenVerifier;
use Lukk\Support\TokenContext;
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
/**
 * The claims of a token the test asserts is VALID.
 *
 * `verify()` is nullable — a rejected token is null — so reading a claim straight off it both hides
 * the failure mode from the analyser and, when a test regresses, reports "property on null" instead
 * of the thing that actually broke. Use `verifier()->verify()` directly when the point of the test
 * IS that verification fails.
 *
 * @return stdClass&object{sub: mixed, jti: mixed, exp: mixed, fid?: mixed, scope?: mixed, pin?: mixed, iss?: mixed, aud?: mixed}
 */
function claims(string $token): object
{
    $claims = verifier()->verify($token);

    expect($claims)->not->toBeNull();
    assert($claims !== null);

    return $claims;
}

/**
 * The authenticated user inside a test route closure, narrowed.
 *
 * `request()->user()` is nullable, but these closures only ever mount behind `auth:{guard}` — the
 * same reason `ResolvesAuthenticatedUser` exists on the controller side.
 *
 * @return Authenticatable&HasTokenAbilities
 */
function actor()
{
    $user = request()->user();

    assert($user !== null);

    return $user;
}

/**
 * Run a console command and get something assertable.
 *
 * `$this->artisan()` is typed `PendingCommand|int` — it degrades to an exit code when the console
 * kernel is already running one. Every call here chains `assertSuccessful()`/`expectsOutput…`,
 * which exist only on `PendingCommand`, so assert the shape once instead of at each site.
 *
 * @param  array<string, mixed>  $parameters
 */
function command(string $cmd, array $parameters = []): PendingCommand
{
    $pending = test()->artisan($cmd, $parameters);

    expect($pending)->toBeInstanceOf(PendingCommand::class);
    assert($pending instanceof PendingCommand);

    return $pending;
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

/** A mint-time context for the issuer — subject + family, on the current guard. */
function ctx(int|string $userId, string $familyId = 'fam'): TokenContext
{
    return new TokenContext(Lukk\Lukk::currentGuard(), $userId, $familyId);
}
