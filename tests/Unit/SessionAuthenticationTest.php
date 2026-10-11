<?php

declare(strict_types=1);

use Lukk\Support\SessionAuthentication;

// The session's authentication record is written through `RefreshTokenRepository`, a swap seam, so the
// read re-validates everything: a value lukk's own encoder would not have written reads as unknown.

it('reads a record up to its bound, and nothing longer', function () {
    $atBound = str_pad('{"auth_time":5', SessionAuthentication::MAX_LENGTH - 1, ' ').'}';

    expect(strlen($atBound))->toBe(SessionAuthentication::MAX_LENGTH)
        ->and(SessionAuthentication::decode($atBound)->authTime)->toBe(5)
        ->and(SessionAuthentication::decode(' '.$atBound)->authTime)->toBeNull();
});

it('takes only a non-negative integer for the sign-in time', function (mixed $stored, ?int $expected) {
    expect(SessionAuthentication::decode((string) json_encode(['auth_time' => $stored]))->authTime)->toBe($expected);
})->with([
    'the epoch' => [0, 0],
    'a time' => [1_760_000_000, 1_760_000_000],
    'before the epoch' => [-1, null],
    'a numeric string' => ['5', null],
    'a fraction' => [1.5, null],
]);

it('reads the legacy bare list as methods with no time, and anything else as nothing', function () {
    $legacy = SessionAuthentication::decode('["pwd","otp","mfa"]');

    expect([$legacy->methods, $legacy->authTime])->toBe([['pwd', 'otp', 'mfa'], null])
        ->and(SessionAuthentication::decode('{"amr":{"a":"pwd"},"auth_time":5}')->methods)->toBeNull()
        ->and(SessionAuthentication::decode('5')->methods)->toBeNull()
        ->and(SessionAuthentication::decode(null)->authTime)->toBeNull();
});

it('encodes nothing when it knows nothing', function () {
    expect((new SessionAuthentication(null, null))->encode())->toBeNull()
        ->and((new SessionAuthentication(['pwd'], null))->encode())->toBe('{"amr":["pwd"]}');
});
