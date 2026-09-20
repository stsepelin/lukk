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

it('leaves alone a session that started while logout-all was running', function (string $method) {
    // The window between the bulk revoke's SELECT and its UPDATE: a sign-in on another device lands there.
    // Both engines' UPDATE sees that row (READ COMMITTED takes a new snapshot per statement; InnoDB's UPDATE
    // is a current read), so revoking by the query rather than by the family ids it read revoked a session
    // that was never denylisted and never returned — signed out a refresh later, with nothing to show why.
    $repo = app(RefreshTokenRepository::class);
    $user = User::factory()->create();
    $repo->persist($user->getKey(), 'keep', null, hash('sha256', 'keep'), now()->addDay()->getTimestamp());
    $repo->persist($user->getKey(), 'old', null, hash('sha256', 'old'), now()->addDay()->getTimestamp());
    $late = fn () => $repo->persist($user->getKey(), 'late', null, hash('sha256', 'late'), now()->addDay()->getTimestamp());

    $revoked = $method === 'all'
        ? $repo->revokeUserFamilies($user->getKey(), $late)
        : $repo->revokeUserFamiliesExcept($user->getKey(), 'keep', $late);

    expect($revoked)->not->toContain('late')
        ->and(DB::table('refresh_tokens')->where('family_id', 'late')->value('revoked_at'))->toBeNull()
        ->and(DB::table('refresh_tokens')->where('family_id', 'old')->value('revoked_at'))->not->toBeNull();
})->with(['all', 'except']);

it('reads once and writes nothing for a user with no live session', function () {
    // Logout-all on an account with nothing to end — an erased account, a second click — must not pay two
    // UPDATEs over an empty id list.
    $repo = app(RefreshTokenRepository::class);
    $user = User::factory()->create();
    $queries = [];
    DB::listen(function ($query) use (&$queries) {
        $queries[] = strtolower($query->sql);
    });

    expect($repo->revokeUserFamilies($user->getKey()))->toBe([]);
    expect(array_values(array_filter($queries, fn (string $sql) => str_starts_with($sql, 'update'))))->toBe([]);
});
