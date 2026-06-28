<?php

declare(strict_types=1);

use Lukk\Actions\RevokeSession;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\LoginResponse;
use Lukk\Support\TokenPair;
use Lukk\Tests\Fixtures\User;

/**
 * These lock in the customization seams advertised in the README: an app should
 * be able to rebind any contract and have the package use the replacement,
 * without editing package code.
 */
it('lets an app reshape login output by rebinding the LoginResponse contract', function () {
    app()->bind(LoginResponse::class, fn ($app, array $params) => new class($params['pair']) implements LoginResponse
    {
        public function __construct(private TokenPair $pair) {}

        public function toResponse($request)
        {
            return response()->json(['custom' => true, 'at' => $this->pair->accessToken]);
        }
    });

    User::factory()->create(['email' => 'swap@y.com']);

    $this->postJson('/auth/login', ['email' => 'swap@y.com', 'password' => 'password'])
        ->assertOk()
        ->assertJson(['custom' => true])
        ->assertJsonMissing(['refresh_token']);
});

it('lets an app swap the Denylist implementation behind the contract', function () {
    $fake = new class implements Denylist
    {
        /** @var array<int,string> */
        public array $revokedFamilies = [];

        public function revokeJti(string $jti, int $ttlSeconds): void {}

        public function revokeFamily(string $familyId, int $ttlSeconds): void
        {
            $this->revokedFamilies[] = $familyId;
        }

        public function has(string $type, string $id): bool
        {
            return false;
        }

        public function hasAny(array $types): bool
        {
            return false;
        }
    };

    app()->instance(Denylist::class, $fake);

    app(RevokeSession::class)('fam-xyz');

    expect($fake->revokedFamilies)->toBe(['fam-xyz']);
});
