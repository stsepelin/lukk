<?php

declare(strict_types=1);

use Lukk\Actions\RevokeAllSessions;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Tests\Fixtures\User;

/** A denylist that records every write, so a test can count them. */
function recordingDenylist(): Denylist
{
    return new class implements Denylist
    {
        public array $writes = [];

        public function revokeJti(string $jti, int $ttlSeconds): void
        {
            $this->writes[] = ['jti', $jti];
        }

        public function revokeFamily(string $familyId, int $ttlSeconds): void
        {
            $this->writes[] = ['fid', $familyId];
        }

        public function has(string $type, string $id): bool
        {
            return false;
        }

        public function hasAny(array $types): bool
        {
            return false;
        }
    };
}

it('denylists the presenting token\'s own lukk family once, with the rest', function () {
    $user = User::factory()->create();
    $pair = start()($user->getKey());
    $family = notNull(app(RefreshTokenRepository::class)->findByHash(issuer()->hash($pair->refreshToken)))->familyId;
    $denylist = recordingDenylist();
    app()->instance(Denylist::class, $denylist);

    app(RevokeAllSessions::class)($user->getKey(), (object) ['fid' => $family, 'jti' => 'j', 'exp' => time() + 60]);

    expect($denylist->writes)->toBe([['fid', $family]]);
});

it('ends nothing more for a presented token it cannot name', function (array $claims) {
    // No `fid` and no `jti` leaves nothing to denylist it by; an `exp` that is no number cannot date the entry.
    $denylist = recordingDenylist();
    app()->instance(Denylist::class, $denylist);

    app(RevokeAllSessions::class)(User::factory()->create()->getKey(), (object) $claims);

    expect($denylist->writes)->toBe([]);
})->with([
    'no jti' => [['exp' => time() + 60]],
    'an empty jti' => [['jti' => '', 'exp' => time() + 60]],
    'no exp' => [['jti' => 'j']],
    'an exp that is no number' => [['jti' => 'j', 'exp' => 'soon']],
]);

it('presents nothing for the internal callers', function () {
    $denylist = recordingDenylist();
    app()->instance(Denylist::class, $denylist);

    app(RevokeAllSessions::class)(User::factory()->create()->getKey());

    expect($denylist->writes)->toBe([]);
});

it('takes ids a co-issuer encoded as numbers, and a fractional exp', function () {
    // JSON has one number type: `"fid": 4242`, `"jti": 4243` and a fractional `exp` are all legal in a
    // co-issued token, and the denylist takes strings and whole seconds.
    $this->freezeSecond();
    $denylist = recordingDenylist();
    app()->instance(Denylist::class, $denylist);
    $user = User::factory()->create()->getKey();

    app(RevokeAllSessions::class)($user, (object) ['fid' => 4242]);
    app(RevokeAllSessions::class)($user, (object) ['jti' => 4243, 'exp' => time() + 60.5]);

    expect($denylist->writes)->toBe([['fid', '4242'], ['jti', '4243']]);
});

it('keeps a presented token on the denylist for at least a second, however close to expiry', function () {
    $this->freezeSecond();
    $ttls = [];
    app()->instance(Denylist::class, new class($ttls) implements Denylist
    {
        public function __construct(private array &$ttls) {}

        public function revokeJti(string $jti, int $ttlSeconds): void
        {
            $this->ttls[] = $ttlSeconds;
        }

        public function revokeFamily(string $familyId, int $ttlSeconds): void {}

        public function has(string $type, string $id): bool
        {
            return false;
        }

        public function hasAny(array $types): bool
        {
            return false;
        }
    });

    app(RevokeAllSessions::class)(User::factory()->create()->getKey(), (object) ['jti' => 'late', 'exp' => time() - 3600]);
    app(RevokeAllSessions::class)(User::factory()->create()->getKey(), (object) ['jti' => 'live', 'exp' => (string) (time() + 60)]);

    expect($ttls)->toBe([1, 60 + Lukk\Lukk::leeway(Lukk\Lukk::guardConfig())]);
});
