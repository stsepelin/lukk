<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Schema;
use Lukk\Actions\DeleteAccount;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Lukk;
use Lukk\Tests\Fixtures\AuthConnection;
use Lukk\Tests\Fixtures\AuthConnectionName;
use Lukk\Tests\Fixtures\OtherConnectionRefreshToken;
use Lukk\Tests\Fixtures\OtherConnectionUser;
use Lukk\Tests\Fixtures\User;

/*
 * lukk supports a model on its own connection — refresh tokens through `useRefreshTokenModel`, users in a
 * shared directory database, a broker with `auth.passwords.*.connection`. A transaction or schema check
 * opened on the DEFAULT connection then guards nothing: the row lock is taken in autocommit and released
 * at once, and a table that lives elsewhere reads as missing.
 */

beforeEach(function () {
    config(['database.connections.lukk_other' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => false]]);
    DB::purge('lukk_other');
});

function onOtherConnection(Closure $migrate): void
{
    $default = DB::getDefaultConnection();
    DB::setDefaultConnection('lukk_other');
    try {
        $migrate();
    } finally {
        DB::setDefaultConnection($default);
    }
}

it('opens the rotation transaction on the refresh-token model\'s own connection', function () {
    // Else `findByHashForUpdate` locks in autocommit and the rotate/reuse decision is not atomic.
    Lukk::useRefreshTokenModel(OtherConnectionRefreshToken::class);

    $level = app(RefreshTokenRepository::class)->transaction(fn () => DB::connection('lukk_other')->transactionLevel());

    expect($level)->toBe(1);
});

it('revokes a user\'s families inside a transaction on that connection too', function () {
    onOtherConnection(fn () => (require __DIR__.'/../../database/migrations/2026_01_01_000000_create_refresh_tokens_table.php')->up());
    Lukk::useRefreshTokenModel(OtherConnectionRefreshToken::class);
    $seen = null;

    app(RefreshTokenRepository::class)->revokeUserFamilies(1, function () use (&$seen) {
        $seen = DB::connection('lukk_other')->transactionLevel();
    });

    expect($seen)->toBe(1);
});

it('locks a recovery code\'s row inside a transaction on the user\'s own connection', function () {
    // Two concurrent redemptions of one code could otherwise both re-read it and both succeed.
    // The existing fixture's `directory` connection, as the cross-connection erasure tests use it.
    config(['database.connections.directory' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']]);
    DB::purge('directory');
    Schema::connection('directory')->create('users', fn (Blueprint $table) => $this->defineUsersTable($table));
    $user = OtherConnectionUser::query()->create(['email' => 'dir@y.com', 'password' => 'x']);
    $user->forceFill(['two_factor_recovery_codes' => json_encode([Hash::make('CODE-1')])])->save();
    $levels = [];
    DB::listen(function (QueryExecuted $query) use (&$levels) {
        if ($query->connectionName === 'directory' && str_starts_with(strtolower($query->sql), 'select')) {
            $levels[] = $query->connection->transactionLevel();
        }
    });

    expect($user->useRecoveryCode('CODE-1'))->toBeTrue()
        ->and(max($levels))->toBe(1);
});

it('erases the reset row of a broker that keeps its table on another connection', function () {
    // The row holds a plaintext email address; a check on the default connection read the table as missing.
    onOtherConnection(fn () => Schema::create('password_reset_tokens', function (Blueprint $table) {
        $table->string('email')->primary();
        $table->string('token');
        $table->timestamp('created_at')->nullable();
    }));
    Schema::drop('password_reset_tokens');
    config(['auth.passwords.users.connection' => 'lukk_other']);
    app()->forgetInstance('auth.password');
    Password::clearResolvedInstances();
    $user = User::factory()->create(['email' => 'gone@y.com']);
    Password::broker()->createToken($user);
    expect(DB::connection('lukk_other')->table('password_reset_tokens')->count())->toBe(1);

    app(DeleteAccount::class)($user);

    expect(DB::connection('lukk_other')->table('password_reset_tokens')->count())->toBe(0);
});

it('keeps the default-connection erasure atomic when refresh tokens live on another connection', function () {
    // The erasure transaction followed the refresh-token connection, so the passkey and reset-row
    // deletes on the default one ran in autocommit: a disposal that then threw left an account that
    // still exists with no way to sign in — the outcome the single transaction exists to prevent.
    onOtherConnection(fn () => (require __DIR__.'/../../database/migrations/2026_01_01_000000_create_refresh_tokens_table.php')->up());
    Lukk::useRefreshTokenModel(OtherConnectionRefreshToken::class);
    config(['lukk.features.lockout' => true]);
    $user = User::factory()->create(['email' => 'atomic@y.com']);
    DB::table('passkeys')->insert(['credential_id' => 'c1', 'user_id' => $user->id, 'guard' => Lukk::currentGuard(), 'public_key' => 'x', 'sign_count' => 0]);
    Password::broker()->createToken($user);
    Lukk::deleteUserUsing(fn () => throw new RuntimeException('disposal failed'));

    expect(fn () => app(DeleteAccount::class)($user))->toThrow(RuntimeException::class, 'disposal failed');

    expect(User::query()->whereKey($user->id)->exists())->toBeTrue()
        ->and(DB::table('passkeys')->where('user_id', $user->id)->count())->toBe(1)
        ->and(DB::table('password_reset_tokens')->count())->toBe(1);
});

it('rolls back the reset-row delete on the broker\'s own connection when the disposal fails', function () {
    onOtherConnection(fn () => Schema::create('password_reset_tokens', function (Blueprint $table) {
        $table->string('email')->primary();
        $table->string('token');
        $table->timestamp('created_at')->nullable();
    }));
    config(['auth.passwords.users.connection' => 'lukk_other']);
    app()->forgetInstance('auth.password');
    Password::clearResolvedInstances();
    $user = User::factory()->create(['email' => 'broker-atomic@y.com']);
    Password::broker()->createToken($user);
    Lukk::deleteUserUsing(fn () => throw new RuntimeException('disposal failed'));

    expect(fn () => app(DeleteAccount::class)($user))->toThrow(RuntimeException::class, 'disposal failed');

    expect(DB::connection('lukk_other')->table('password_reset_tokens')->count())->toBe(1);
});

it('erases on a broker connection named by an enum, which Laravel accepts', function (UnitEnum $connection) {
    onOtherConnection(fn () => Schema::create('password_reset_tokens', function (Blueprint $table) {
        $table->string('email')->primary();
        $table->string('token');
        $table->timestamp('created_at')->nullable();
    }));
    config(['auth.passwords.users.connection' => $connection]);
    app()->forgetInstance('auth.password');
    Password::clearResolvedInstances();
    $user = User::factory()->create(['email' => 'enum@y.com']);
    Password::broker()->createToken($user);

    app(DeleteAccount::class)($user);

    expect(DB::connection('lukk_other')->table('password_reset_tokens')->count())->toBe(0);
})->with(['backed' => [AuthConnection::Other], 'pure' => [AuthConnectionName::lukk_other]]);
