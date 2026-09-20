<?php

declare(strict_types=1);

use Illuminate\Support\Facades\RateLimiter;
use Lukk\Tests\FalsyGuardsTestCase;
use Lukk\Tests\Fixtures\User;

uses(FalsyGuardsTestCase::class)->group('multi-guard');

it('boots with lukk.guards set to false, registering nothing for a phantom guard named 0', function () {
    // `(array) false` is `[0 => false]`: the limiter loop registered `lukk-0-login` and friends,
    // and a string cast dropped from that loop turned it into a TypeError inside boot().
    expect(RateLimiter::limiter('lukk-0-login'))->toBeNull()
        ->and(RateLimiter::limiter('lukk-0-refresh'))->toBeNull()
        ->and(RateLimiter::limiter('lukk-0-claim'))->toBeNull()
        ->and(RateLimiter::limiter('lukk-0-2fa'))->toBeNull()
        ->and(RateLimiter::limiter('lukk-login'))->not->toBeNull();

    $user = User::factory()->create();
    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])->assertOk();
});
