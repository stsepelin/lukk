<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Models\RefreshToken;
use Lukk\Support\SessionAuthentication;
use Lukk\Tests\Fixtures\ObservedRefreshToken;
use Lukk\Tests\Fixtures\TenantScopedRefreshToken;
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

it('writes the row without amr when the column probe fails, rather than failing the sign-in', function () {
    // A blip, a deadlock, a statement timeout: skipping `amr` for this one write is the safe direction,
    // and nothing is cached, so the next write asks again. The probe's own schema query is made to fail
    // once — `Schema::connection()` is a static facade method, so it cannot be mocked.
    $armed = true;
    DB::listen(function ($query) use (&$armed) {
        if ($armed && str_contains(strtolower($query->sql), 'pragma')) {
            $armed = false;
            throw new RuntimeException('probe failed');
        }
    });

    $first = start()(1, ['amr' => ['pwd']]);
    $second = start()(1, ['amr' => ['pwd']]);

    $amrOf = fn ($pair) => RefreshToken::query()->where('token_hash', issuer()->hash($pair->refreshToken))->value('amr');
    expect($armed)->toBeFalse()
        ->and($amrOf($first))->toBeNull()
        ->and(SessionAuthentication::decode($amrOf($second))->methods)->toBe(['pwd']);
});

it('asks the database nothing about a family id that is no UUID', function () {
    // A co-issuer's `fid` (`42`, `"sess_42"`) names no family lukk minted, and on PostgreSQL comparing it
    // with the native `uuid` column is SQLSTATE 22P02 — a 500 (tests/Concurrency/CoIssuerTokenTest.php).
    // sqlite compares anything, so the property pinned here is that no such comparison is ever issued.
    $repo = app(RefreshTokenRepository::class);
    $user = User::factory()->create();
    $queries = [];
    DB::listen(function ($query) use (&$queries) {
        $queries[] = $query->sql;
    });

    $pinned = $repo->familyIsPinned('sess_42');
    $repo->revokeFamily('42');

    expect($pinned)->toBeFalse()->and($queries)->toBe([]);

    $repo->revokeUserFamiliesExcept($user->getKey(), 'sess_42');

    expect(implode(' ', $queries))->not->toContain('"family_id" !=');
});

it('still spares the caller\'s own family, and finds a pinned one, by its UUID', function () {
    $repo = app(RefreshTokenRepository::class);
    $user = User::factory()->create();
    $mine = start()($user->getKey(), [], ['ci.deploy']);
    $other = start()($user->getKey());
    $family = fn ($pair) => notNull($repo->findByHash(issuer()->hash($pair->refreshToken)))->familyId;

    expect($repo->familyIsPinned($family($mine)))->toBeTrue();

    $repo->revokeUserFamiliesExcept($user->getKey(), $family($mine));

    expect(notNull($repo->findByHash(issuer()->hash($mine->refreshToken)))->revokedAt)->toBeNull()
        ->and(notNull($repo->findByHash(issuer()->hash($other->refreshToken)))->revokedAt)->not->toBeNull();

    $repo->revokeFamily($family($mine));
    expect(notNull($repo->findByHash(issuer()->hash($mine->refreshToken)))->revokedAt)->not->toBeNull();
});

it('runs no model event while it writes a refresh token, so no application code runs under the rotation lock', function () {
    // `persist()` runs inside `RotateRefreshToken`'s transaction, under the parent row's `FOR UPDATE`. A
    // `save()` there fired the model's events, so an observer on a `useRefreshTokenModel` subclass ran under
    // the lock — the hazards CLAUDE.md lists for every consumer callback: a slow one serialises the family's
    // refreshes, and on PostgreSQL a swallowed failing query turns COMMIT into ROLLBACK (pinned in
    // tests/Concurrency/RefreshRevokeRaceTest.php).
    $seen = [];
    ObservedRefreshToken::$onEvent = function (string $event) use (&$seen) {
        $seen[] = $event;
    };
    Lukk\Lukk::useRefreshTokenModel(ObservedRefreshToken::class);

    rotate()(start()(User::factory()->create()->getKey())->refreshToken);

    ObservedRefreshToken::$onEvent = null;
    expect($seen)->toBe([]);
});

it('writes the row even where a listener would have cancelled it', function () {
    // A `creating` listener returning false made `save()` return false and write NOTHING — silently, so
    // rotation handed back a pair whose refresh token was never stored, and the client was logged out on
    // its next refresh. lukk's own rows are not the application's to veto.
    ObservedRefreshToken::$onEvent = fn (string $event) => $event === 'creating' ? false : null;
    Lukk\Lukk::useRefreshTokenModel(ObservedRefreshToken::class);

    $rotated = rotate()(start()(User::factory()->create()->getKey())->refreshToken);

    ObservedRefreshToken::$onEvent = null;
    expect(app(RefreshTokenRepository::class)->findByHash(issuer()->hash($rotated->refreshToken)))->not->toBeNull();
});

it('refuses to report a write that did not happen', function () {
    // The model's `save()` is the consumer's to override; one answering false wrote nothing, and the
    // rotation that called it must fail rather than hand out a token with no row behind it.
    Lukk\Lukk::useRefreshTokenModel(get_class(new class extends RefreshToken
    {
        protected $table = 'refresh_tokens';

        public function saveQuietly(array $options = [])
        {
            return false;
        }
    }));

    expect(fn () => start()(User::factory()->create()->getKey()))
        ->toThrow(RuntimeException::class, 'lukk could not store a refresh token');
});

it('leaves a required column to the model as it is built, since no creating listener runs', function () {
    // A `BelongsToTenant`-style trait filling `tenant_id` from `creating` no longer runs for lukk's quiet
    // write (and a NOT NULL column then fails the insert). What still runs is the model's construction:
    // `$attributes` defaults and a trait's `initialize…()` method — the seam UPGRADE.md documents, with no
    // event dispatched under the rotation lock.
    Schema::table('refresh_tokens', function ($table) {
        $table->string('tenant_id')->nullable();
        $table->string('tenant_from_creating')->nullable();
    });
    TenantScopedRefreshToken::$tenant = 'acme';
    Lukk\Lukk::useRefreshTokenModel(TenantScopedRefreshToken::class);

    $rotated = rotate()(start()(User::factory()->create()->getKey())->refreshToken);

    TenantScopedRefreshToken::$tenant = null;
    expect(DB::table('refresh_tokens')->pluck('tenant_id')->all())->toBe(['acme', 'acme'])
        ->and(DB::table('refresh_tokens')->whereNotNull('tenant_from_creating')->exists())->toBeFalse()
        ->and(app(RefreshTokenRepository::class)->findByHash(issuer()->hash($rotated->refreshToken)))->not->toBeNull();
});
