<?php

declare(strict_types=1);

use Lukk\Tests\AccountDeletionDisabledTestCase;
use Lukk\Tests\Fixtures\User;

// Routes register at boot, so the flag has to be set before the provider runs.
uses(AccountDeletionDisabledTestCase::class)->group('account-deletion');

it('registers no erasure route when the feature is off', function () {
    // On by DEFAULT, so this is the switch an operator reaches for when deletion is handled
    // elsewhere — a support workflow, a retention obligation, an identity provider that owns the
    // account. It has to actually un-register the route, not merely refuse inside the controller.
    $pair = User::factory()->create()->startSession();

    $this->withToken($pair->accessToken)->deleteJson('/auth/account')->assertNotFound();
});
