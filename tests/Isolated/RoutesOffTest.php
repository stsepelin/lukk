<?php

declare(strict_types=1);

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Lukk\Tests\Fixtures\User;
use Lukk\Tests\RoutesOffTestCase;

uses(RoutesOffTestCase::class);

it('mounts no route when lukk.routes is off', function () {
    expect(lukkRoutes()->map(fn ($route) => $route->uri())->all())->toBe([]);
});

it('leaves the notification links alone when it does not own the routes they would point at', function () {
    // The features are on, but the verify route is not registered here: pointing the notification at
    // its name would make every verification email throw `Route [lukk.verification.verify] not defined`.
    expect(VerifyEmail::$createUrlCallback)->toBeNull()
        ->and(ResetPassword::$createUrlCallback)->toBeNull();
});

it('still verifies tokens: the guard does not depend on the routes', function () {
    $user = User::factory()->create();

    app('router')->get('/whoami', fn () => ['id' => auth('api')->id()])->middleware('auth:api');

    $this->withToken($user->startSession()->accessToken)->getJson('/whoami')->assertOk()->assertJson(['id' => $user->getKey()]);
});
