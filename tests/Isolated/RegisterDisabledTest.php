<?php

declare(strict_types=1);

use Lukk\Tests\RegistrationDisabledTestCase;

// Lives outside Feature/ so this file can bind its own base case — one that boots with
// `features.registration` off — to prove the /auth/register route is gated when the flag is false.
uses(RegistrationDisabledTestCase::class)->group('registration');

it('does not expose the /auth/register route when the feature is off', function () {
    $this->postJson('/auth/register', [
        'email' => 'a@b.c',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ])->assertNotFound();
});
