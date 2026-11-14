<?php

declare(strict_types=1);

use Lukk\Models\RefreshToken;
use Lukk\Tests\DegradedIdentityTestCase;
use Lukk\Tests\Fixtures\User;

uses(DegradedIdentityTestCase::class);

it('signs in only the account the identifier names when lukk.username is empty', function () {
    // An empty column made the lookup `"" = ?` on SQLite — two string literals, true for every row —
    // so the FIRST account matched any identifier and its password signed in whoever typed it.
    $first = User::factory()->create(['email' => 'first@example.test']);
    $second = User::factory()->create(['email' => 'second@example.test', 'password' => bcrypt('second-password')]);

    $this->postJson('/auth/login', ['email' => 'nobody@example.test', 'password' => 'password'])->assertStatus(422);
    app('auth')->forgetGuards();

    $access = $this->postJson('/auth/login', ['email' => 'second@example.test', 'password' => 'second-password'])
        ->assertOk()->json('access_token');

    expect(claims($access)->sub)->toBe((string) $second->getKey())
        ->and($first->getKey())->not->toBe($second->getKey());
});

it('mounts the routes at /auth and names the default guard api when path and guard are null', function () {
    config(['lukk.cookie_mode' => true]);
    User::factory()->create(['email' => 'ada@example.test']);

    $response = $this->postJson('/auth/login', ['email' => 'ada@example.test', 'password' => 'password'])->assertOk();

    expect($response->headers->getCookies()[0]->getName())->toBe('__Host-refresh')
        ->and(RefreshToken::query()->value('guard'))->toBeIn([null, 'api']);
});

it('still mounts the routes whose feature flag defaults on when the flag is missing', function (string $method, string $uri) {
    // Absent is a config cached before the key existed, not a decision to switch the feature off: a
    // silently unmounted route is a 404 on a documented endpoint with nothing in the log to explain it.
    $mounted = collect(app('router')->getRoutes())
        ->contains(fn ($route) => $route->uri() === $uri && in_array($method, $route->methods(), true));

    expect($mounted)->toBeTrue();
})->with([
    'logout_all' => ['DELETE', 'auth/sessions'],
    'account_deletion: erasure' => ['DELETE', 'auth/account'],
    'account_deletion: export' => ['GET', 'auth/account/export'],
    'change_password' => ['POST', 'auth/password'],
]);
