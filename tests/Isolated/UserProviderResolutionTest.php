<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Lukk\Lukk;
use Lukk\Tests\Fixtures\Admin;
use Lukk\Tests\MultiGuardTestCase;

uses(MultiGuardTestCase::class)->group('multi-guard');

afterEach(fn () => Lukk::$registerUsing = null);

it('signs the default guard in against the provider lukk.user_provider names', function () {
    // Ignoring the setting would fall back to `users` — and an admin, who exists only in `admins`,
    // could not sign in.
    config(['lukk.user_provider' => 'admins']);
    $admin = Admin::factory()->create(['email' => 'boss@example.test']);

    $this->postJson('/auth/login', ['email' => $admin->email, 'password' => 'password'])->assertOk();
});

it('registers into the model behind lukk.user_provider', function () {
    config(['lukk.user_provider' => 'admins']);

    $this->postJson('/auth/register', ['name' => 'New', 'email' => 'new@example.test', 'password' => 'a-long-password', 'password_confirmation' => 'a-long-password'])
        ->assertSuccessful();

    expect(DB::table('admins')->where('email', 'new@example.test')->exists())->toBeTrue()
        ->and(DB::table('users')->where('email', 'new@example.test')->exists())->toBeFalse();
});
