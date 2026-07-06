<?php

declare(strict_types=1);

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

    // Cross-guard: each token is refused by the other guard (signature + audience mismatch).
    $this->withToken($adminToken)->postJson('/auth/logout')->assertStatus(401);
    forget();
    $this->withToken($userToken)->postJson('/admin/auth/logout')->assertStatus(401);

    // Sanity: each token authorizes its own guard.
    forget();
    $this->withToken($userToken)->postJson('/auth/logout')->assertSuccessful();
    forget();
    $this->withToken($adminToken)->postJson('/admin/auth/logout')->assertSuccessful();
});

it('rejects a cross-guard token by audience alone, even with a shared secret', function () {
    // Give the admin guard the users guard's secret — only the audience now differs.
    config(['lukk.guards.admin.secret' => str_repeat('a', 64)]);
    $adminToken = Admin::factory()->create()->startSession()->accessToken;

    // Signature verifies (shared key) but the users guard's audience allowlist rejects it.
    $this->withToken($adminToken)->postJson('/auth/logout')->assertStatus(401);
    forget();
    $this->withToken($adminToken)->postJson('/admin/auth/logout')->assertSuccessful();
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

    $this->withToken($token)->postJson('/admin/auth/logout')->assertSuccessful();
    forget();
    $this->withToken($token)->postJson('/auth/logout')->assertStatus(401);
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
