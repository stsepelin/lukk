<?php

declare(strict_types=1);

use Lukk\Tests\DisabledFeatureTestCase;
use Lukk\Tests\Fixtures\User;

// Routes register during boot, so the flag has to be off before the provider runs.
DisabledFeatureTestCase::$disable = ['change_password'];

uses(DisabledFeatureTestCase::class)->group('change-password');

it('does not register the route when the feature is off', function () {
    // Off is a real configuration — an app whose passwords live in an identity provider shouldn't
    // expose an endpoint that writes to a column it doesn't own.
    expect(collect(app('router')->getRoutes())->contains(fn ($r) => $r->uri() === 'auth/password'))->toBeFalse();

    $pair = User::factory()->create()->startSession();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertStatus(404);
});
