<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Lukk\Events\RefreshTokenReused;
use Lukk\Exceptions\InvalidRefreshToken;
use Lukk\Models\RefreshToken;

uses()->group('refresh');

// Freeze the clock so timestamps come from one instant. The grace check compares
// integer-second timestamps (`rotated_at + grace < now`); without freezing, the
// gap between a real `rotate()` and a later `travel()` can straddle a wall-clock
// second and shift the effective delta by 1s, flaking the exact-boundary cases.
beforeEach(fn () => $this->freezeSecond());

function familyId(): string
{
    return RefreshToken::query()->value('family_id');
}

it('issues a usable pair at login and stores only the hash', function () {
    $pair = start()(1);

    expect($pair->accessToken)->toBeString()->and($pair->expiresIn)->toBe(900);
    expect(RefreshToken::count())->toBe(1);
    expect(RefreshToken::where('token_hash', hash('sha256', $pair->refreshToken))->exists())->toBeTrue();
    expect(RefreshToken::where('token_hash', $pair->refreshToken)->exists())->toBeFalse();
});

it('rotates: stamps the parent and chains a successor in the same family', function () {
    $pair = start()(7);
    $out = rotate()($pair->refreshToken);

    expect($out->refreshToken)->not->toBe($pair->refreshToken);
    $rows = RefreshToken::orderBy('created_at')->get();
    expect($rows)->toHaveCount(2);
    expect($rows[0]->rotated_at)->not->toBeNull();
    expect($rows[1]->previous_id)->toBe($rows[0]->id);
    expect($rows[1]->family_id)->toBe($rows[0]->family_id);
});

it('rejects an unknown refresh token', function () {
    expect(fn () => rotate()('nope'))->toThrow(InvalidRefreshToken::class);
});

it('rejects an unknown refresh token without any side effects', function () {
    start()(1);
    $before = RefreshToken::count();

    expect(fn () => rotate()('never-issued'))->toThrow(InvalidRefreshToken::class);

    expect(RefreshToken::count())->toBe($before);
    expect(RefreshToken::whereNotNull('revoked_at')->count())->toBe(0);
});

it('rejects an expired refresh token', function () {
    config(['lukk.refresh_ttl' => 1]);
    $pair = start()(1);
    $this->travel(5)->seconds();
    expect(fn () => rotate()($pair->refreshToken))->toThrow(InvalidRefreshToken::class);
});

it('tolerates concurrent reuse within the grace window without logging out', function () {
    $pair = start()(1);
    $first = rotate()($pair->refreshToken);
    $second = rotate()($pair->refreshToken);

    expect($second->refreshToken)->not->toBe($first->refreshToken);
    expect(RefreshToken::where('family_id', familyId())->whereNotNull('revoked_at')->count())->toBe(0);
    expect(RefreshToken::where('family_id', familyId())->count())->toBe(3);
});

it('tolerates a replay at exactly the grace boundary (pins < not <=)', function () {
    config(['lukk.grace_seconds' => 30]);
    $pair = start()(1);
    rotate()($pair->refreshToken);

    $this->travel(30)->seconds();

    $sibling = rotate()($pair->refreshToken);

    expect($sibling->refreshToken)->toBeString();
    expect(RefreshToken::where('family_id', familyId())->whereNotNull('revoked_at')->count())->toBe(0);
});

it('revokes the whole family when a consumed token is replayed after grace', function () {
    $pair = start()(1);
    rotate()($pair->refreshToken);
    $this->travel(31)->seconds();

    try {
        rotate()($pair->refreshToken);
        $this->fail('expected InvalidRefreshToken');
    } catch (InvalidRefreshToken $e) {
        expect($e->reason)->toBe('reuse');
    }

    expect(RefreshToken::where('family_id', familyId())->whereNull('revoked_at')->count())->toBe(0);
});

it('dispatches a security event when a reused token triggers a family revoke', function () {
    Event::fake([RefreshTokenReused::class]);

    $pair = start()(1);
    rotate()($pair->refreshToken);
    $this->travel(31)->seconds();
    $fid = familyId();

    expect(fn () => rotate()($pair->refreshToken))->toThrow(InvalidRefreshToken::class);

    Event::assertDispatched(
        RefreshTokenReused::class,
        fn (RefreshTokenReused $e) => $e->familyId === $fid && $e->reason === 'reuse',
    );
});

it('kills the family if a hard-revoked token is presented', function () {
    $pair = start()(1);
    revokeSession()(familyId());

    try {
        rotate()($pair->refreshToken);
        $this->fail('expected InvalidRefreshToken');
    } catch (InvalidRefreshToken $e) {
        expect($e->reason)->toBe('revoked');
    }
});

it('revoke-all revokes only that user', function () {
    start()(42);
    start()(42);
    start()(99);
    revokeAll()(42);

    expect(RefreshToken::where('user_id', 42)->whereNull('revoked_at')->count())->toBe(0);
    expect(RefreshToken::where('user_id', 99)->whereNull('revoked_at')->count())->toBe(1);
});

it('denylists the family so its access tokens stop verifying immediately', function () {
    $pair = start()(99);
    expect(verifier()->verify($pair->accessToken))->not->toBeNull();

    revokeSession()(familyId());
    expect(verifier()->verify($pair->accessToken))->toBeNull();
});
