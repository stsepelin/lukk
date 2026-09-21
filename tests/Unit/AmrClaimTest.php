<?php

declare(strict_types=1);

use Lukk\Actions\StartSession;

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
