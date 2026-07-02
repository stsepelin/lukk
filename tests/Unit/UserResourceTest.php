<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Lukk\Http\Resources\UserResource;
use Lukk\Tests\Fixtures\User;

it('emits id + a true email_verified for a verified MustVerifyEmail user', function () {
    $user = User::factory()->create(['email_verified_at' => now()]);

    expect((new UserResource($user))->toArray(Request::create('/')))
        ->toMatchArray(['id' => $user->getAuthIdentifier(), 'email_verified' => true]);
});

it('emits email_verified false for an unverified user', function () {
    $user = User::factory()->create(['email_verified_at' => null]);

    expect((new UserResource($user))->toArray(Request::create('/')))
        ->toMatchArray(['email_verified' => false]);
});

it('emits email_verified null when the model is not MustVerifyEmail', function () {
    $data = (new UserResource(new GenericUser(['id' => 42])))->toArray(Request::create('/'));

    expect($data)->toBe(['id' => 42, 'email_verified' => null]);
});

it('lets a subclass add its own fields via fields()', function () {
    $user = User::factory()->create(['email' => 'a@b.c', 'email_verified_at' => now()]);

    $resource = new class($user) extends UserResource
    {
        protected function fields(Request $request): array
        {
            return ['email' => $this->email];
        }
    };

    expect($resource->toArray(Request::create('/')))
        ->toMatchArray(['id' => $user->getAuthIdentifier(), 'email_verified' => true, 'email' => 'a@b.c']);
});

it('wraps in a `data` key as a response (which lukk-js auto-unwraps)', function () {
    $user = User::factory()->create(['email_verified_at' => now()]);

    $json = UserResource::make($user)->response(Request::create('/'))->getData(true);

    expect($json)->toHaveKey('data')
        ->and($json['data']['id'])->toBe($user->getAuthIdentifier());
});
