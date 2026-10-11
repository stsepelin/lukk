<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Lukk\Models\RefreshToken;
use Lukk\Tests\Fixtures\OtherConnectionRefreshToken;

it('prunes expired tokens but keeps active and revoked-but-unexpired ones', function () {
    // One soon-to-expire token (pruned)...
    config(['lukk.refresh_ttl' => 1]);
    start()(1);

    // ...one long-lived active token (kept)...
    config(['lukk.refresh_ttl' => 2592000]);
    start()(2);

    // ...and one revoked-but-unexpired token — KEPT so a replay still resolves to `reuse`
    // (fires the reuse event + family cascade) instead of a generic `unknown` reject.
    start()(3);
    revokeSession()(RefreshToken::where('user_id', 3)->value('family_id'));

    $this->travel(5)->seconds();

    command('lukk:prune')
        ->expectsOutputToContain('Pruned 1 refresh token(s).')
        ->assertSuccessful();

    expect(RefreshToken::count())->toBe(2);
    expect(RefreshToken::where('user_id', 2)->exists())->toBeTrue();
    expect(RefreshToken::where('user_id', 3)->exists())->toBeTrue();
});

it('reports each sweep it ran', function () {
    command('lukk:prune')
        ->expectsOutputToContain('Pruned 0 lockout counter(s).')
        ->expectsOutputToContain('Pruned 0 orphaned passkey(s).')
        ->assertSuccessful();
});

it('skips the refresh-token sweep where the table was never published, as on a verify-only service', function () {
    // The prune is scheduled by default and runs on every install, including a resource server that only
    // verifies tokens and never published `refresh_tokens`. Unguarded, it threw there every day — the
    // passkey and lockout sweeps beside it already check for their tables.
    Schema::drop('refresh_tokens');

    command('lukk:prune')
        ->expectsOutputToContain('Pruned 0 refresh token(s).')
        ->assertSuccessful();
});

it('looks for the refresh-token table on the model\'s own connection', function () {
    // A `useRefreshTokenModel` subclass on another connection: the default connection having no such
    // table says nothing about it, and the sweep must still run there.
    config(['database.connections.lukk_other' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => false]]);
    DB::purge('lukk_other');
    DB::connection('lukk_other')->getSchemaBuilder()->create('refresh_tokens', function ($table) {
        $table->string('id')->primary();
        $table->timestamp('expires_at');
    });
    DB::connection('lukk_other')->table('refresh_tokens')->insert(['id' => 'r1', 'expires_at' => now()->subDay()]);
    Schema::drop('refresh_tokens');
    Lukk\Lukk::useRefreshTokenModel(OtherConnectionRefreshToken::class);

    command('lukk:prune')
        ->expectsOutputToContain('Pruned 1 refresh token(s).')
        ->assertSuccessful();
});
