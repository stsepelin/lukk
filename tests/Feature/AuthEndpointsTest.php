<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Lukk\Actions\RevokeAllSessions;
use Lukk\Contracts\Denylist;
use Lukk\Events\RefreshTokenReused;
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

it('refuses a refresh token presented in the query string', function () {
    // `$request->input()` unions the query for every content type, so this used to work — putting a
    // 30-day opaque credential into access logs, proxy logs and Referer headers (RFC 9700 §4.3.2).
    $pair = User::factory()->create()->startSession();

    // Rejected as an absent token, not honoured from the URL.
    $this->postJson('/auth/refresh?refresh_token='.$pair->refreshToken)->assertStatus(401);

    // And the token is unspent — the request never reached rotation, so the body form still works.
    $this->postJson('/auth/refresh', ['refresh_token' => $pair->refreshToken])->assertOk();
});

it('does not report an ordinary post-logout retry as token reuse', function () {
    // `revoked` is the normal path for a client that still held a refresh token across a logout.
    // Apps are told to treat RefreshTokenReused as a theft signal, so a drip of benign events is
    // alert fatigue over the one alarm that matters.
    Event::fake([RefreshTokenReused::class]);
    $pair = User::factory()->create()->startSession();

    revokeSession()((string) DB::table('refresh_tokens')->value('family_id'));

    $this->postJson('/auth/refresh', ['refresh_token' => $pair->refreshToken])->assertStatus(401);

    Event::assertNotDispatched(RefreshTokenReused::class);
});

it('denylists every family before revoking the rows on logout-all', function () {
    // `RevokeSession` documents the ordering and obeys it; the bulk paths did the opposite, so a
    // cache failure partway left families revoked in the DB but still authenticating for up to
    // access_ttl — during the one operation a user performs BECAUSE they think they're compromised.
    $user = User::factory()->create();
    $user->startSession();
    $user->startSession();

    $seen = [];
    app()->instance(Denylist::class, new class($seen) implements Denylist
    {
        public function __construct(public &$seen) {}

        public function revokeJti(string $jti, int $ttlSeconds): void {}

        public function revokeFamily(string $familyId, int $ttlSeconds): void
        {
            // Captured at the moment of the denylist write: the rows must still be live.
            $this->seen[] = DB::table('refresh_tokens')->whereNull('revoked_at')->count();
        }

        public function has(string $type, string $id): bool
        {
            return false;
        }

        public function hasAny(array $types): bool
        {
            return false;
        }
    });

    app(RevokeAllSessions::class)($user->getKey());

    expect($seen)->not->toBeEmpty()->and(min($seen))->toBeGreaterThan(0);
});
