<?php

declare(strict_types=1);

use Lukk\Contracts\LockoutRepository;

uses()->group('lockout');

beforeEach(fn () => $this->freezeSecond());

/** The repository the container builds for the lockout config set here, and when it would release a lock. */
function lockoutFor(array $lockout): array
{
    config(['lukk.lockout' => $lockout]);
    $repo = app(LockoutRepository::class);

    for ($i = 0; $i < $repo->maxAttempts(); $i++) {
        $repo->recordFailure('login', 'subject-'.md5(serialize($lockout)), null);
    }

    return [$repo->maxAttempts(), $repo->availableIn('login', 'subject-'.md5(serialize($lockout)), null)];
}

it('reads numeric settings, including the strings env() delivers', function () {
    expect(lockoutFor(['max_attempts' => '3', 'release_after' => '30']))->toBe([3, 30]);
});

it('clamps the attempt cap to 1..100 — NIST SP 800-63B §5.2.2\'s ceiling, and never "locked from the start"', function () {
    expect(lockoutFor(['max_attempts' => '150', 'release_after' => 0])[0])->toBe(100)
        ->and(lockoutFor(['max_attempts' => '0', 'release_after' => 0])[0])->toBe(1)
        ->and(lockoutFor(['max_attempts' => '1', 'release_after' => 0])[0])->toBe(1)
        ->and(lockoutFor(['max_attempts' => '100', 'release_after' => 0])[0])->toBe(100);
});

it('never releases on a negative timer, and keeps a zero as "manual release only"', function () {
    // This pins the outcome, not the provider's `max(0, …)`: every reader of `release_after` treats
    // anything `<= 0` as "manual release only", so the clamp alone decides nothing.
    expect(lockoutFor(['max_attempts' => 2, 'release_after' => '-5'])[1])->toBeNull()
        ->and(lockoutFor(['max_attempts' => 2, 'release_after' => '0'])[1])->toBeNull()
        ->and(lockoutFor(['max_attempts' => 2, 'release_after' => '1'])[1])->toBe(1);
});

it('treats a non-numeric setting as unset, rather than as the 0 it would cast to', function () {
    // "abc" is truthy but casts to 0: an attempt cap of 0 would lock every account on its first typo.
    expect(lockoutFor(['max_attempts' => 'abc', 'release_after' => 'abc']))->toBe([100, null]);
});

it('uses the defaults when the lockout block is missing altogether', function () {
    config(['lukk.lockout' => null]);

    expect(app(LockoutRepository::class)->maxAttempts())->toBe(100);
});
