<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Lukk\Actions\RevokeAllSessions;
use Lukk\Contracts\Denylist;
use Lukk\Events\RefreshTokenReused;
use Lukk\Lukk;
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

    $currentFid = claims($current->accessToken)->fid;

    $this->withToken($current->accessToken)->deleteJson('/auth/sessions/others')->assertNoContent();

    expect(RefreshToken::where('family_id', $currentFid)->whereNull('revoked_at')->exists())->toBeTrue();
    expect(RefreshToken::where('family_id', '!=', $currentFid)->whereNull('revoked_at')->count())->toBe(0);
});

it('requires authentication for the session-collection endpoints', function () {
    // `POST /auth/logout` is deliberately NOT here: it also accepts the refresh token, so a client
    // with an expired access token can still end its session. See LogoutTest.
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

it('keeps rotation, reuse detection and the denylist on under a stale config that says false', function () {
    // A config published before these keys were removed still carries them, and the deep merge never
    // deletes a key. They must stay inert: nothing may start reading them as an off switch.
    config([
        'lukk.features.rotation' => false,
        'lukk.features.reuse_detection' => false,
        'lukk.features.denylist' => false,
        'lukk.grace_seconds' => 0,
    ]);
    Event::fake([RefreshTokenReused::class]);
    $pair = User::factory()->create()->startSession();

    // Rotation: the token is consumed and a successor minted.
    $this->postJson('/auth/refresh', ['refresh_token' => $pair->refreshToken])->assertOk();
    expect(RefreshToken::whereNotNull('rotated_at')->count())->toBe(1);

    // Reuse detection: replaying the consumed token past grace kills the family.
    $this->travel(5)->seconds();
    $this->postJson('/auth/refresh', ['refresh_token' => $pair->refreshToken])->assertUnauthorized();
    Event::assertDispatched(RefreshTokenReused::class);

    // Denylist: the family's access token no longer verifies.
    expect(verifier()->verify($pair->accessToken))->toBeNull();
});

it('keeps the caller\'s refresh cookie when revoking other sessions in cookie mode', function () {
    // The response was `LogoutResponse`, which in cookie mode clears the refresh cookie — but this
    // route keeps the calling session alive. The client lost the ability to refresh a session the
    // server still considered live, and was logged out ~15 minutes later on its next refresh.
    config(['lukk.cookie_mode' => true]);
    $user = User::factory()->create();
    $other = $user->startSession();
    $current = $user->startSession();

    $response = $this->withToken($current->accessToken)->deleteJson('/auth/sessions/others')
        ->assertNoContent();

    expect($response->getContent())->toBe('')
        ->and($response->headers->getCookies())->toBeEmpty();

    // Other sessions are gone; the caller's cookie still refreshes.
    $this->postJson('/auth/refresh', ['refresh_token' => $other->refreshToken])->assertUnauthorized();
    $this->withCredentials()->withUnencryptedCookie('__Host-refresh', $current->refreshToken)
        ->postJson('/auth/refresh')->assertOk();
});

it('answers a 401 with the WWW-Authenticate challenge RFC 6750 §3 requires', function () {
    // "The resource server MUST include the HTTP `WWW-Authenticate` response header field." lukk
    // emitted it on 403 (`insufficient_scope`, with the scope that would have sufficed) and on nothing
    // else — so a generic OAuth client was told why it was refused at 403 and nothing at 401, unable to
    // tell "expired, refresh and retry" from "wrong audience, give up".
    $user = User::factory()->create();
    $expired = $this->travel(-3600)->seconds(fn () => $user->startSession()->accessToken);

    // No credential at all: there is no token to call invalid, so the bare challenge is right.
    $this->postJson('/auth/session/claim')->assertUnauthorized()
        ->assertHeader('WWW-Authenticate', 'Bearer');

    app('auth')->forgetGuards();
    foreach ([$expired, 'not-a-jwt'] as $bad) {
        app('auth')->forgetGuards();
        $header = $this->withToken($bad)->postJson('/auth/session/claim')
            ->assertUnauthorized()->headers->get('WWW-Authenticate');

        expect($header)->toContain('error="invalid_token"');
    }
});

it('revokes nothing for a bearer that names no session — it would otherwise mean "every one"', function () {
    // A co-issuer sharing the secret mints tokens with no `fid`. "Others" is defined relative to THIS
    // session, and with no family to except, the call has no way to spare the caller's own: forcing the
    // guard true hands `RevokeOtherSessions` an empty family id, and every session goes — including the
    // one making the request. The route answers 204 either way, so only the sessions tell them apart.
    $user = User::factory()->create();
    $kept = $user->startSession();
    $cfg = Lukk::guardConfig();
    $token = JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => (string) $user->getAuthIdentifier(),
        'jti' => 'co-issued-others', 'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);

    $this->withToken($token)->deleteJson('/auth/sessions/others')->assertNoContent();

    expect(RefreshToken::whereNull('revoked_at')->count())->toBe(1);
    app('auth')->forgetGuards();
    $this->postJson('/auth/refresh', ['refresh_token' => $kept->refreshToken])->assertOk();
});

it('answers revoke-other-sessions with a bare 204 in body mode too', function () {
    $user = User::factory()->create();
    $user->startSession();
    $current = $user->startSession();

    $response = $this->withToken($current->accessToken)->deleteJson('/auth/sessions/others')->assertNoContent();

    expect($response->getContent())->toBe('')
        ->and($response->headers->getCookies())->toBeEmpty();
    $this->postJson('/auth/refresh', ['refresh_token' => $current->refreshToken])->assertOk();
});

it('revokes a family in two statements, closing the PostgreSQL snapshot window', function () {
    // The race itself only reproduces on a real PostgreSQL (tests/Concurrency), which replays both paths'
    // own statements. Pinned structurally here too, so the sqlite suite sees it: one UPDATE per statement
    // snapshot, BOTH limited to the families already read and denylisted — an UPDATE by the user's query
    // would also revoke a session committed after that read, which nothing denylisted or returned.
    $user = User::factory()->create();
    $user->startSession();
    $user->startSession();

    $updates = [];
    DB::listen(function ($query) use (&$updates) {
        if (str_starts_with(strtolower($query->sql), 'update "refresh_tokens"')) {
            $updates[] = $query->sql;
        }
    });

    revokeAll()($user->getKey());
    expect($updates)->toHaveCount(2)
        ->each->toContain('"family_id" in');

    $updates = [];
    revokeSession()((string) RefreshToken::value('family_id'));
    expect($updates)->toHaveCount(2);
});
