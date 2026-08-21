<?php

declare(strict_types=1);

use Lukk\Tests\ChangePasswordDisabledTestCase;
use Lukk\Tests\Fixtures\User;

// One subclass per configuration — the flag has to be set before the provider boots, and a shared
// mutable static would be won by whichever test file happened to load last.
uses(ChangePasswordDisabledTestCase::class)->group('change-password');

it('does not register the route when the feature is off', function () {
    // Off is a real configuration — an app whose passwords live in an identity provider shouldn't
    // expose an endpoint that writes to a column it doesn't own.
    expect(collect(app('router')->getRoutes())->contains(fn ($r) => $r->uri() === 'auth/password'))->toBeFalse();

    $pair = User::factory()->create()->startSession();

    $this->withToken($pair->accessToken)->postJson('/auth/password', [
        'current_password' => 'password', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1',
    ])->assertStatus(404);
});
