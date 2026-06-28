<?php

declare(strict_types=1);

use Lukk\Contracts\Denylist;
use Lukk\Models\RefreshToken;
use Lukk\Tests\Fixtures\User;

uses()->group('refresh');

it('rotates the pair via the refresh endpoint (token in body, BFF mode)', function () {
    $user = User::factory()->create();
    $pair = $user->startSession();

    $this->postJson('/auth/refresh', ['refresh_token' => $pair->refreshToken])
        ->assertOk()
        ->assertJsonStructure(['access_token', 'refresh_token', 'token_type', 'expires_in']);

    // Old token rotated; a successor now exists in the same family.
    expect(RefreshToken::count())->toBe(2);
});

it('returns 401 (not 500) for an unknown refresh token', function () {
    $this->postJson('/auth/refresh', ['refresh_token' => 'not-a-real-token'])
        ->assertUnauthorized()
        ->assertJsonStructure(['message']);
});

it('returns 401 (not 500) when refreshing a revoked session', function () {
    $user = User::factory()->create();
    $pair = $user->startSession();
    $user->revokeAllSessions();

    $this->postJson('/auth/refresh', ['refresh_token' => $pair->refreshToken])->assertUnauthorized();
});

it('reads the refresh token from the __Host- cookie in cookie mode', function () {
    config(['lukk.cookie_mode' => true]);
    $user = User::factory()->create();
    $pair = $user->startSession();

    $this->withCredentials()
        ->withUnencryptedCookie('__Host-refresh', $pair->refreshToken)
        ->postJson('/auth/refresh')
        ->assertOk()
        // cookie mode: access token in the body, refresh back in the cookie
        ->assertJsonStructure(['access_token', 'token_type', 'expires_in'])
        ->assertJsonMissing(['refresh_token'])
        ->assertCookie('__Host-refresh');
});

it('revokes the session via the logout endpoint', function () {
    $user = User::factory()->create();
    $pair = $user->startSession();
    $fid = RefreshToken::query()->value('family_id');

    $this->withToken($pair->accessToken)->postJson('/auth/logout')->assertNoContent();

    expect(RefreshToken::where('family_id', $fid)->whereNull('revoked_at')->count())->toBe(0);
    expect(app(Denylist::class)->has('fid', $fid))->toBeTrue();
});

it('revokes every session via DELETE /sessions', function () {
    $user = User::factory()->create();
    $user->startSession();
    $current = $user->startSession();

    $this->withToken($current->accessToken)->deleteJson('/auth/sessions')->assertNoContent();

    expect(RefreshToken::where('user_id', $user->id)->whereNull('revoked_at')->count())->toBe(0);
});

it('revokes other sessions but keeps the calling one via DELETE /sessions/others', function () {
    $user = User::factory()->create();
    $user->startSession();              // another device
    $current = $user->startSession();   // the caller

    $currentFid = verifier()->verify($current->accessToken)->fid;

    $this->withToken($current->accessToken)->deleteJson('/auth/sessions/others')->assertNoContent();

    expect(RefreshToken::where('family_id', $currentFid)->whereNull('revoked_at')->exists())->toBeTrue();
    expect(RefreshToken::where('family_id', '!=', $currentFid)->whereNull('revoked_at')->count())->toBe(0);
});

it('requires authentication for the logout endpoints', function () {
    $this->postJson('/auth/logout')->assertUnauthorized();
    $this->deleteJson('/auth/sessions')->assertUnauthorized();
    $this->deleteJson('/auth/sessions/others')->assertUnauthorized();
});
