<?php

declare(strict_types=1);

use Lukk\Tests\TwoFactorPerGuardTestCase;

uses(TwoFactorPerGuardTestCase::class)->group('multi-guard', 'two-factor');

it('mounts the challenge redemption from each guard\'s own flag', function () {
    $mounted = fn (string $uri) => collect(app('router')->getRoutes())
        ->contains(fn ($route) => $route->uri() === $uri && in_array('POST', $route->methods(), true));

    expect($mounted('admin/auth/two-factor-challenge'))->toBeTrue()
        ->and($mounted('auth/two-factor-challenge'))->toBeFalse();
});
