<?php

declare(strict_types=1);

use Lukk\Contracts\Denylist;
use Lukk\Lukk;
use Lukk\Models\RefreshToken;
use Lukk\Tests\Fixtures\User;

afterEach(function () {
    // Static hub state must not leak between tests.
    Lukk::$refreshTokenModel = null;
});

it('defaults the refresh-token model and lets an app swap it', function () {
    expect(Lukk::refreshTokenModel())->toBe(RefreshToken::class);

    Lukk::useRefreshTokenModel(MyRefreshToken::class);

    expect(Lukk::refreshTokenModel())->toBe(MyRefreshToken::class);
});

it('authenticates a user for the current request via actingAs', function () {
    $user = User::factory()->create();

    Lukk::actingAs($user);

    expect(auth()->guard('api')->user())->not->toBeNull()
        ->and(auth()->guard('api')->user()->is($user))->toBeTrue();
});

it('exposes sessions and revokes them via the HasRefreshTokens trait', function () {
    $user = User::factory()->create();
    $user->startSession();
    $user->startSession();

    expect($user->refreshTokens()->count())->toBe(2);

    $user->revokeAllSessions();

    expect($user->refreshTokens()->whereNull('revoked_at')->count())->toBe(0);
});

it('short-circuits the denylist lookup for an empty id', function () {
    // Empty id never touches the cache store and is always allowed.
    expect(app(Denylist::class)->has('jti', ''))->toBeFalse();
    expect(app(Denylist::class)->has('fid', ''))->toBeFalse();
    expect(app(Denylist::class)->hasAny(['jti' => '', 'fid' => '']))->toBeFalse();
});

class MyRefreshToken extends RefreshToken {}
