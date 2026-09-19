<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Tests\Fixtures\User;

uses()->group('refresh');

it('answers a miss without ever taking the row lock', function () {
    // `FOR UPDATE` on an absent unique value gap-locks under MySQL REPEATABLE READ, so a probe for a token
    // that does not exist must not reach it. One existence check, and nothing after.
    $repo = app(RefreshTokenRepository::class);
    $queries = [];
    DB::listen(function ($query) use (&$queries) {
        $queries[] = $query->sql;
    });

    expect($repo->findByHashForUpdate(hash('sha256', 'no-such-token')))->toBeNull()
        ->and($queries)->toHaveCount(1);
});

it('reads a row whose created_at was never set', function () {
    // A row migrated in from an older schema, or written by hand: the timestamp is optional in the record,
    // and a missing one must read as unknown rather than fail the refresh that found it.
    $repo = app(RefreshTokenRepository::class);
    $user = User::factory()->create();
    $repo->persist($user->getKey(), 'fam', null, hash('sha256', 't'), now()->addDay()->getTimestamp());
    DB::table('refresh_tokens')->where('family_id', 'fam')->update(['created_at' => null]);

    expect(notNull($repo->findByHash(hash('sha256', 't')))->createdAt)->toBeNull();
});
