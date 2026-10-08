<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Support\Str;
use Lukk\Actions\StartSession;
use Lukk\Auth\ChallengeToken;
use Lukk\Tests\Fixtures\User;

uses()->group('refresh');

// `amr` is stored with the family and re-stamped by every rotation, so what may enter the column —
// and what may come back out of it — is a security boundary, not a formatting detail.

it('refuses to store an amr that is not a bounded list of strings', function () {
    // The column is durable and re-stamped by every rotation, so an unbounded or malformed value is
    // no longer a token that dies in one access_ttl — it bricks the family for its whole
    // refresh_ttl, every request 431ing at the proxy with no way out but a fresh sign-in. `scope` is
    // bounded for exactly this reason. And the read side mirrors the write side rather than trusting
    // it, because `RefreshTokenRepository` is a documented swap seam.
    $encode = fn (mixed $v) => StartSession::encodeAmr($v);

    expect($encode(['pwd', 'otp']))->toBe('["pwd","otp"]')
        ->and($encode([]))->toBeNull()
        ->and($encode('pwd'))->toBeNull()
        ->and($encode(['role' => 'admin']))->toBeNull()   // an object, not a list
        ->and($encode(['pwd', 5]))->toBeNull()            // not all strings
        ->and($encode(['pwd', '']))->toBeNull()           // an empty method names nothing
        ->and($encode([str_repeat('a', 65)]))->toBeNull() // one method too long
        ->and($encode(array_fill(0, 40, 'webauthn')))->toBeNull(); // the whole claim too long
});

it('bounds the claim at the sizes the docblock and CHANGELOG promise', function () {
    // Literal, deliberately. The behavioural test below derives its payload FROM the constants, so
    // it proves the bound is ENFORCED but moves with any value — `MAX_AMR_LENGTH = 440` passed it.
    // Since `amr` is durable and re-stamped by every rotation, the actual numbers are the promise
    // (RFC 8176's registered values are short; `scope` is bounded at 128/2048 for the same reason),
    // so the numbers get an assertion of their own.
    expect(StartSession::MAX_AMR_METHOD_LENGTH)->toBe(64)
        ->and(StartSession::MAX_AMR_LENGTH)->toBe(256);
});

it('bounds a method and the whole claim at exactly the documented sizes', function () {
    // BOTH sides of each boundary. Testing only the rejecting side left the numbers unpinned: with
    // just a 65-character case, `MAX_AMR_METHOD_LENGTH = 8` passed, and with a 441-byte payload
    // `MAX_AMR_LENGTH = 440` passed — so the constants could drift far from what the docblock and
    // the CHANGELOG promise without a single test noticing.
    $encode = fn (mixed $v) => StartSession::encodeAmr($v);

    expect($encode([str_repeat('a', StartSession::MAX_AMR_METHOD_LENGTH)]))->not->toBeNull()
        ->and($encode([str_repeat('a', StartSession::MAX_AMR_METHOD_LENGTH + 1)]))->toBeNull();

    // The claim bound needs SEVERAL methods, since one may not exceed the per-method bound. Grow a
    // list until its JSON lands exactly on the limit, so the assertion is about the constant rather
    // than about a payload that happens to be over it.
    $methods = [];
    while (strlen((string) json_encode([...$methods, 'x'])) <= StartSession::MAX_AMR_LENGTH) {
        $methods[] = str_repeat('m', StartSession::MAX_AMR_METHOD_LENGTH);
    }

    array_pop($methods);
    $last = StartSession::MAX_AMR_LENGTH - strlen((string) json_encode([...$methods, '']));
    $atLimit = [...$methods, str_repeat('z', $last)];

    expect(strlen((string) json_encode($atLimit)))->toBe(StartSession::MAX_AMR_LENGTH)
        ->and($encode($atLimit))->not->toBeNull()
        ->and($encode([...$methods, str_repeat('z', $last + 1)]))->toBeNull();
});

it('re-validates a challenge amr instead of widening it', function (mixed $claimed) {
    // `firstFactorOf()` reads a claim from a token this process signed, but `decode()` does not
    // type-check it and a co-issuer sharing the secret can mint any shape. A `(array)` cast WIDENS
    // rather than validates — it promotes a bare string to `["pwd"]` and a numeric-keyed object to a
    // list — so shapes `encodeAmr` refuses everywhere else would have been accepted here and stamped
    // into a real session's `amr`. Both the guard and the round-trip were prose until now.
    //
    // (A JSON object with numeric keys is NOT among these: PHP decodes `{"0":"pwd"}` to the list
    // `['pwd']`, so it is indistinguishable from one and accepting it is correct.)
    $user = User::factory()->create();
    $tokens = app(ChallengeToken::class);

    // Mint by hand, so the claim carries a shape `issue()` would itself refuse to write.
    $cfg = Lukk\Lukk::guardConfig();
    $now = time();
    $challenge = JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => (string) $user->getAuthIdentifier(),
        'jti' => (string) Str::uuid(), 'iat' => $now, 'nbf' => $now, 'exp' => $now + 300,
        'gid' => 'api', 'amr' => $claimed,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => '2fa+challenge']);

    expect($tokens->firstFactorOf('2fa', $challenge))->toBeNull();
})->with([
    'a bare string' => ['pwd'],
    'an object' => [['role' => 'admin']],
    'a number' => [7],
    'a nested list' => [[['pwd']]],
    'oversized' => [array_fill(0, 40, 'webauthn')],
]);
