<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use Lukk\Actions\RevokeAllSessions;
use Lukk\Contracts\Denylist;
use Lukk\Models\RefreshToken;
use Lukk\Tests\Fixtures\Admin;
use Lukk\Tests\Fixtures\User;
use Lukk\Tests\MultiGuardTestCase;

// Two isolated guards (users + admins) with distinct crypto identities; see MultiGuardTestCase.
uses(MultiGuardTestCase::class)->group('multi-guard');

/** Drop the resolved-guard memoization so two requests in one test act as different principals. */
function forget(): void
{
    app('auth')->forgetGuards();
}

it('rejects a token minted for one guard on another (distinct secrets)', function () {
    $userToken = User::factory()->create()->startSession()->accessToken;
    $adminToken = Admin::factory()->create()->startSession()->accessToken;

    // Cross-guard: each token is refused by the other guard (signature + audience mismatch). Probed
    // on an `auth:{guard}` route — logout no longer 401s, since it also accepts a refresh token.
    $this->withToken($adminToken)->deleteJson('/auth/sessions/others')->assertStatus(401);
    forget();
    $this->withToken($userToken)->deleteJson('/admin/auth/sessions/others')->assertStatus(401);

    // Sanity: each token authorizes its own guard.
    forget();
    $this->withToken($userToken)->deleteJson('/auth/sessions/others')->assertSuccessful();
    forget();
    $this->withToken($adminToken)->deleteJson('/admin/auth/sessions/others')->assertSuccessful();
});

it('rejects a cross-guard token by audience alone, even with a shared secret', function () {
    // Give the admin guard the users guard's secret — only the audience now differs.
    config(['lukk.guards.admin.secret' => str_repeat('a', 64)]);
    $adminToken = Admin::factory()->create()->startSession()->accessToken;

    // Signature verifies (shared key) but the users guard's audience allowlist rejects it.
    $this->withToken($adminToken)->deleteJson('/auth/sessions/others')->assertStatus(401);
    forget();
    $this->withToken($adminToken)->deleteJson('/admin/auth/sessions/others')->assertSuccessful();
});

it('scopes refresh rotation to the minting guard', function () {
    $adminPair = Admin::factory()->create()->startSession();

    // The admin refresh token is invisible to the users guard's repository...
    $this->postJson('/auth/refresh', ['refresh_token' => $adminPair->refreshToken])->assertStatus(401);
    // ...but rotates on its own guard.
    $this->postJson('/admin/auth/refresh', ['refresh_token' => $adminPair->refreshToken])
        ->assertOk()
        ->assertJsonStructure(['access_token', 'refresh_token']);
});

it('logs in on the admin guard against the admins provider, minting an admin-only token', function () {
    Admin::factory()->create(['email' => 'boss@corp.com']);

    $token = $this->postJson('/admin/auth/login', ['email' => 'boss@corp.com', 'password' => 'password'])
        ->assertOk()
        ->json('access_token');

    $this->withToken($token)->deleteJson('/admin/auth/sessions/others')->assertSuccessful();
    forget();
    $this->withToken($token)->deleteJson('/auth/sessions/others')->assertStatus(401);
});

it('does not authenticate a users-table account on the admin guard', function () {
    User::factory()->create(['email' => 'user@corp.com']); // in users, not admins

    $this->postJson('/admin/auth/login', ['email' => 'user@corp.com', 'password' => 'password'])
        ->assertStatus(422);
});

it('scopes the login throttle per guard (no cross-guard account lockout)', function () {
    User::factory()->create(['email' => 'shared@corp.com']);
    Admin::factory()->create(['email' => 'shared@corp.com']);

    // Trip the admin login's per-account/per-ip bucket for the shared email.
    foreach (range(1, 5) as $i) {
        $this->postJson('/admin/auth/login', ['email' => 'shared@corp.com', 'password' => 'wrong']);
    }
    $this->postJson('/admin/auth/login', ['email' => 'shared@corp.com', 'password' => 'password'])->assertStatus(429);

    // The users guard's login for the same email is a separate bucket — unaffected.
    $this->postJson('/auth/login', ['email' => 'shared@corp.com', 'password' => 'password'])->assertSuccessful();
});

it('serves each guard its own JWKS (per-guard signing keys)', function () {
    $keys = rsaKeypair();
    config([
        'lukk.guards.admin.algorithm' => 'RS256',
        'lukk.guards.admin.keys' => [
            'active' => 'admin-key',
            'private' => $keys['private'],
            'public' => ['admin-key' => $keys['public']],
        ],
    ]);

    $adminKeys = $this->getJson('/admin/auth/jwks')->assertOk()->json('keys');
    $usersKeys = $this->getJson('/auth/jwks')->assertOk()->json('keys');

    // The admin guard publishes its own RS256 key; the default (HS256) guard publishes none.
    expect($adminKeys)->toHaveCount(1)
        ->and($adminKeys[0]['kid'])->toBe('admin-key')
        ->and($usersKeys)->toBe([]);
});

it('revokes only the target guard\'s families on logout-all, despite colliding ids', function () {
    $user = User::factory()->create();   // users.id = 1
    $admin = Admin::factory()->create(); // admins.id = 1 — colliding id
    expect($user->getKey())->toBe($admin->getKey());

    $userPair = $user->startSession();
    $adminPair = $admin->startSession();

    // Revoke every ADMIN session for id 1.
    $admin->revokeAllSessions();

    // The admin family is dead; the users family (same id) is untouched.
    $this->postJson('/admin/auth/refresh', ['refresh_token' => $adminPair->refreshToken])->assertStatus(401);
    $this->postJson('/auth/refresh', ['refresh_token' => $userPair->refreshToken])->assertOk();
});

it('throttles the extra guard\'s confirm-password on its own limiter', function () {
    // A `throttle:lukk-admin-confirm` that the provider never registered would 500 the route, so
    // this pins the per-guard registration as much as the bucketing. The per-guard limiters read
    // their config once at boot (like the login/refresh ones beside them), so this uses the
    // shipped default of 5 rather than overriding it at runtime.
    Admin::factory()->create(['email' => 'root@corp.com']);
    $access = $this->postJson('/admin/auth/login', ['email' => 'root@corp.com', 'password' => 'password'])
        ->json('access_token');

    foreach (range(1, 5) as $i) {
        app('auth')->forgetGuards();
        $this->withToken($access)->postJson('/admin/auth/confirm-password', ['password' => 'wrong-pw'])
            ->assertStatus(422);
    }

    app('auth')->forgetGuards();
    $this->withToken($access)->postJson('/admin/auth/confirm-password', ['password' => 'wrong-pw'])
        ->assertStatus(429);

    // A separate bucket from the default guard's, which is untouched.
    app('auth')->forgetGuards();
    $this->postJson('/auth/confirm-password', ['password' => 'wrong-pw'])->assertStatus(401);
});

it('refuses a step-up confirmation earned on another guard, even for a colliding id', function () {
    // `lukk.confirm` used to resolve its verifier from `lukk.set-guard`, which never runs on a
    // consumer's own route — so an admin route verified step-up against the USERS guard's key and
    // audience, and a confirmation earned on the users guard satisfied the admin gate.
    Route::middleware(['auth:admin', 'lukk.confirm'])
        ->delete('/_test/admin-sensitive', fn () => response()->json(['ok' => true]));

    $user = User::factory()->create(['email' => 'attacker@x.com']);
    $admin = Admin::factory()->create(['email' => 'root@corp.com']);

    // The premise of the attack: ids collide across the two providers.
    expect((string) $user->getKey())->toBe((string) $admin->getKey());

    forget();
    $confirmation = $this->withToken($user->startSession()->accessToken)
        ->postJson('/auth/confirm-password', ['password' => 'password'])
        ->assertOk()->json('confirmation_token');

    // A stolen admin access token plus a users-guard confirmation must not open the gate.
    forget();
    $this->withToken($admin->startSession()->accessToken)
        ->withHeaders(['X-Lukk-Confirmation' => $confirmation])
        ->deleteJson('/_test/admin-sensitive')
        ->assertStatus(423);
});

it('accepts a step-up confirmation earned on the guard that owns the route', function () {
    // The mirror of the bug: verifying under the wrong guard also meant an admin's OWN
    // confirmation, minted at `admin/auth/confirm-password`, could never satisfy the gate.
    Route::middleware(['auth:admin', 'lukk.confirm'])
        ->delete('/_test/admin-sensitive', fn () => response()->json(['ok' => true]));

    $admin = Admin::factory()->create(['email' => 'root@corp.com']);

    forget();
    $access = $admin->startSession()->accessToken;
    $confirmation = $this->withToken($access)
        ->postJson('/admin/auth/confirm-password', ['password' => 'password'])
        ->assertOk()->json('confirmation_token');

    forget();
    $this->withToken($access)
        ->withHeaders(['X-Lukk-Confirmation' => $confirmation])
        ->deleteJson('/_test/admin-sensitive')
        ->assertOk();
});

it('gives the extra guard\'s confirm-password a per-user bucket, not just per-IP', function () {
    // Per-IP alone would hand a thief holding a stolen admin token 5 password guesses per source
    // /64 per minute — and the extra guards are the higher-privilege audiences multi-guard exists
    // for. Rotating the address must not buy more attempts.
    $admin = Admin::factory()->create(['email' => 'root@corp.com']);

    forget();
    $access = $this->postJson('/admin/auth/login', ['email' => 'root@corp.com', 'password' => 'password'])
        ->json('access_token');

    foreach (range(1, 5) as $i) {
        forget();
        $this->withToken($access)->withServerVariables(['REMOTE_ADDR' => "198.51.100.{$i}"])
            ->postJson('/admin/auth/confirm-password', ['password' => 'wrong-pw'])
            ->assertStatus(422);
    }

    forget();
    $this->withToken($access)->withServerVariables(['REMOTE_ADDR' => '198.51.100.99'])
        ->postJson('/admin/auth/confirm-password', ['password' => 'wrong-pw'])
        ->assertStatus(429);
});

it('gives each guard its own refresh cookie, so one login cannot destroy the other', function () {
    // Every guard set the same `__Host-refresh` at Path=/. Guards may share a host and differ only
    // by path, so under cookie_mode logging into admin overwrote the users cookie and vice versa —
    // each login silently destroying the other session. The default guard keeps the plain name, so
    // a single-guard app is untouched.
    config(['lukk.cookie_mode' => true]);
    User::factory()->create(['email' => 'user@corp.com']);
    Admin::factory()->create(['email' => 'root@corp.com']);

    forget();
    $users = $this->postJson('/auth/login', ['email' => 'user@corp.com', 'password' => 'password'])->assertOk();

    forget();
    $admin = $this->postJson('/admin/auth/login', ['email' => 'root@corp.com', 'password' => 'password'])->assertOk();

    $name = fn ($response) => collect($response->headers->getCookies())->firstOrFail()->getName();

    expect($name($users))->toBe('__Host-refresh')
        ->and($name($admin))->toBe('__Host-refresh-admin')
        ->and($name($users))->not->toBe($name($admin));
});

it('resolves the acting guard for an action taken on a consumer route', function () {
    // `app(RevokeAllSessions::class)` outside lukk's own route group fell back to the DEFAULT guard,
    // so a "revoke everything" on an `auth:admin` route left the admin's sessions alive and
    // destroyed an unrelated user's — the two ids collide across providers.
    Route::middleware('auth:admin')->delete('/_test/wipe', function () {
        app(RevokeAllSessions::class)(actor()->getAuthIdentifier());

        return response()->json(['ok' => true]);
    });

    $user = User::factory()->create();
    $admin = Admin::factory()->create();
    expect((string) $user->getKey())->toBe((string) $admin->getKey());

    forget();
    $userPair = $user->startSession();
    forget();
    $adminPair = $admin->startSession();

    forget();
    $this->withToken($adminPair->accessToken)->deleteJson('/_test/wipe')->assertOk();

    // The admin's session is gone; the colliding user's survives.
    forget();
    $this->postJson('/admin/auth/refresh', ['refresh_token' => $adminPair->refreshToken])->assertStatus(401);
    forget();
    $this->postJson('/auth/refresh', ['refresh_token' => $userPair->refreshToken])->assertOk();
});

it('never lets a logout on one guard revoke another guard\'s session', function () {
    // Logout no longer requires `auth:{guard}`, so isolation now rests on the verifier (audience +
    // signature) for the bearer and on the guard-scoped repository for the refresh token. Ids collide
    // across the two providers, which is the case that matters.
    $user = User::factory()->create();
    $admin = Admin::factory()->create();
    expect((string) $user->getKey())->toBe((string) $admin->getKey());

    $adminPair = $admin->startSession();
    $adminFamily = (string) RefreshToken::where('guard', 'admin')->value('family_id');

    $live = fn () => RefreshToken::where('guard', 'admin')->whereNull('revoked_at')->count();
    expect($live())->toBe(1);

    // Both of the admin's credentials, presented to the USERS guard's logout.
    forget();
    $this->withToken($adminPair->accessToken)
        ->postJson('/auth/logout', ['refresh_token' => $adminPair->refreshToken])
        ->assertNoContent();

    expect($live())->toBe(1)
        ->and(app(Denylist::class)->has('fid', $adminFamily))->toBeFalse();

    // And on its own guard, the refresh token alone ends it.
    forget();
    $this->postJson('/admin/auth/logout', ['refresh_token' => $adminPair->refreshToken])->assertNoContent();

    expect($live())->toBe(0);
});

it('clears the guard\'s own refresh cookie on logout when only that guard is in cookie mode', function () {
    config(['lukk.cookie_mode' => false, 'lukk.guards.admin.cookie_mode' => true]);
    $adminPair = Admin::factory()->create()->startSession();

    forget();
    $response = $this->withCredentials()
        ->withUnencryptedCookie('__Host-refresh-admin', $adminPair->refreshToken)
        ->postJson('/admin/auth/logout')
        ->assertNoContent();

    expect(collect($response->headers->getCookies())->map->getName()->all())->toBe(['__Host-refresh-admin'])
        ->and(RefreshToken::where('guard', 'admin')->whereNull('revoked_at')->exists())->toBeFalse();

    // The users guard is not in cookie mode, so it sends no clear.
    forget();
    expect($this->postJson('/auth/logout')->assertNoContent()->headers->getCookies())->toBeEmpty();
});

it('keeps a cookie-mode guard\'s own refresh cookie when revoking its other sessions', function () {
    config(['lukk.cookie_mode' => false, 'lukk.guards.admin.cookie_mode' => true]);
    $admin = Admin::factory()->create();
    $other = $admin->startSession();
    $current = $admin->startSession();

    forget();
    $response = $this->withToken($current->accessToken)->deleteJson('/admin/auth/sessions/others')->assertNoContent();

    expect($response->headers->getCookies())->toBeEmpty();

    forget();
    $this->postJson('/admin/auth/refresh', ['refresh_token' => $other->refreshToken])->assertUnauthorized();
    forget();
    $this->withCredentials()->withUnencryptedCookie('__Host-refresh-admin', $current->refreshToken)
        ->postJson('/admin/auth/refresh')->assertOk()->assertCookie('__Host-refresh-admin');
});

it('meters logout lookups per guard, so one guard\'s traffic cannot throttle another\'s', function () {
    config(['lukk.rate_limits.refresh.max_attempts' => 1]);
    $adminPair = Admin::factory()->create()->startSession();

    // Exhaust the USERS guard's lookup budget from this address.
    forget();
    $this->postJson('/auth/logout', ['refresh_token' => 'junk'])->assertNoContent();
    forget();
    $this->postJson('/auth/logout', ['refresh_token' => 'junk'])->assertStatus(429);

    // The admin guard's budget is untouched.
    forget();
    $this->postJson('/admin/auth/logout', ['refresh_token' => $adminPair->refreshToken])->assertNoContent();

    expect(RefreshToken::where('guard', 'admin')->whereNull('revoked_at')->exists())->toBeFalse();
});

it('marks, claims and expires unclaimed sessions per guard', function () {
    // Enabled for the admin guard only. The users guard's sessions are never marked, and an admin's
    // late first use revokes only the admin family, despite colliding ids.
    config(['lukk.access_ttl' => 300, 'lukk.claim_seconds' => 0, 'lukk.guards.admin.claim_seconds' => 600]);
    User::factory()->create(['email' => 'user@corp.com']);
    Admin::factory()->create(['email' => 'root@corp.com']);

    forget();
    $users = $this->postJson('/auth/login', ['email' => 'user@corp.com', 'password' => 'password'])->assertOk()->json();
    forget();
    $admin = $this->postJson('/admin/auth/login', ['email' => 'root@corp.com', 'password' => 'password'])->assertOk()->json();

    $familyOf = fn (string $refresh) => (string) RefreshToken::where('token_hash', hash('sha256', $refresh))->value('family_id');

    expect(Cache::has('lukk:unclaimed:'.$familyOf($users['refresh_token'])))->toBeFalse()
        ->and(Cache::has('lukk:unclaimed:'.$familyOf($admin['refresh_token'])))->toBeTrue();

    $this->travel(601)->seconds();

    forget();
    $this->withToken($users['access_token'])->postJson('/auth/session/claim')->assertNoContent();
    forget();
    $this->withToken($admin['access_token'])->postJson('/admin/auth/session/claim')->assertUnauthorized();

    expect(RefreshToken::where('guard', 'admin')->whereNull('revoked_at')->exists())->toBeFalse()
        ->and(RefreshToken::where('guard', 'api')->whereNull('revoked_at')->exists())->toBeTrue();
});

it('claims an admin session through the admin guard\'s own claim route', function () {
    config(['lukk.access_ttl' => 300, 'lukk.guards.admin.claim_seconds' => 600]);
    Admin::factory()->create(['email' => 'boss@corp.com']);

    forget();
    $admin = $this->postJson('/admin/auth/login', ['email' => 'boss@corp.com', 'password' => 'password'])->assertOk()->json();
    forget();
    $this->withToken($admin['access_token'])->postJson('/admin/auth/session/claim')->assertNoContent();

    $this->travel(601)->seconds();
    forget();
    $this->withToken($admin['access_token'])->postJson('/admin/auth/session/claim')->assertNoContent();
});
