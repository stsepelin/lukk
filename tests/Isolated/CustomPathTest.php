<?php

declare(strict_types=1);

use Lukk\Tests\CustomPathTestCase;

uses(CustomPathTestCase::class);

it('mounts every route under the configured path, the emailed verification link included', function () {
    // The link is registered in a group of its own, outside the JSON-forcing one, and so reads the path
    // a second time: left at the default it would 404 from every verification email of an install
    // mounted anywhere else.
    $uris = lukkRoutes()->map(fn ($route) => $route->uri());

    expect($uris)->toContain('account/auth/login', 'account/auth/email/verify/{id}/{hash}')
        ->and($uris->reject(fn (string $uri) => str_starts_with($uri, 'account/auth/'))->all())->toBe([]);
});
