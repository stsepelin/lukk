<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\Register;
use Lukk\Tests\ConcurrencyTestCase;
use Lukk\Tests\Fixtures\User;

uses(ConcurrencyTestCase::class)->group('concurrency');

/*
 * The registration that loses a race is told "taken", inside a transaction of the caller's too.
 *
 * Two posts of one address both pass `Rule::unique`, and the second INSERT hits the index. lukk then
 * asks whether a row with that identifier exists. Asked with a plain read inside a transaction that
 * had already read, MySQL's REPEATABLE READ answered from that transaction's snapshot — taken before
 * the winner committed — so it saw no row and the violation stayed a 500. Invisible on sqlite, which
 * has no snapshot to be stale; the winner here commits on a second connection, as it would in life.
 */

beforeEach(function () {
    Schema::table('users', fn (Blueprint $table) => $table->unique('email'));
    config(['database.connections.winner' => ConcurrencyTestCase::config(ConcurrencyTestCase::engine())]);
});

afterEach(function () {
    // Never left open: the next test's `db:wipe` would wait on its locks.
    while (DB::transactionLevel() > 0) {
        DB::rollBack();
    }
    DB::purge('winner');
});

$payload = ['name' => 'Second', 'email' => 'raced@example.com', 'password' => 'Str0ng-passw0rd!'];

it('answers "taken" to the registration that lost the race inside the caller\'s transaction', function () use ($payload) {
    DB::beginTransaction();
    // The caller has read: on MySQL's REPEATABLE READ this is where its snapshot is taken. (PostgreSQL
    // is left at its default READ COMMITTED here; at REPEATABLE READ it is the test further down.)
    expect(DB::table('users')->where('email', $payload['email'])->exists())->toBeFalse();

    // The winner, committed on its own connection after that.
    DB::connection('winner')->table('users')->insert(['name' => 'First', 'email' => $payload['email'], 'password' => 'x']);

    try {
        (new Register(User::class, 'email'))($payload);
        $this->fail('The losing registration was accepted.');
    } catch (ValidationException $e) {
        expect($e->errors())->toBe(['email' => [__('validation.unique', ['attribute' => 'email'])]]);
    }

    // The caller's transaction is still usable, and still its own to finish.
    expect(DB::transactionLevel())->toBe(1);
    DB::table('users')->insert(['name' => 'Other', 'email' => 'other@example.com', 'password' => 'x']);
    DB::commit();

    expect(DB::table('users')->orderBy('id')->pluck('email')->all())->toBe([$payload['email'], 'other@example.com']);
});

/** Begin the caller's transaction at REPEATABLE READ — MySQL's default, asked for on PostgreSQL. */
function beginRepeatableRead(): void
{
    DB::beginTransaction();

    if (ConcurrencyTestCase::engine() === 'pgsql') {
        DB::statement('set transaction isolation level repeatable read');
    }
}

it('answers "taken" for a row the caller can see, even one that changed since it looked', function () use ($payload) {
    // The plain read comes first, and is enough here. A locking read is not: on PostgreSQL at REPEATABLE
    // READ, locking a row that was updated after the snapshot fails outright (40001) and takes the
    // caller's transaction with it — for a row the snapshot shows perfectly well.
    DB::table('users')->insert(['name' => 'First', 'email' => $payload['email'], 'password' => 'x']);
    beginRepeatableRead();
    expect(DB::table('users')->where('email', $payload['email'])->exists())->toBeTrue();

    DB::connection('winner')->table('users')->where('email', $payload['email'])->update(['name' => 'Renamed']);

    expect(fn () => (new Register(User::class, 'email'))($payload))->toThrow(ValidationException::class);

    DB::table('users')->insert(['name' => 'Other', 'email' => 'other@example.com', 'password' => 'x']);
    DB::commit();

    expect(DB::table('users')->orderBy('id')->pluck('email')->all())->toBe([$payload['email'], 'other@example.com']);
});

it('leaves the violation the error it was where even a locking read is a snapshot read, and the transaction usable', function () use ($payload) {
    // PostgreSQL at REPEATABLE READ: a row committed since the snapshot is not there to be locked. The
    // loser is not told "taken" — but neither is the caller's transaction lost to the attempt.
    beginRepeatableRead();
    expect(DB::table('users')->where('email', $payload['email'])->exists())->toBeFalse();

    DB::connection('winner')->table('users')->insert(['name' => 'First', 'email' => $payload['email'], 'password' => 'x']);

    expect(fn () => (new Register(User::class, 'email'))($payload))->toThrow(UniqueConstraintViolationException::class);

    DB::table('users')->insert(['name' => 'Other', 'email' => 'other@example.com', 'password' => 'x']);
    expect(DB::table('users')->where('email', 'other@example.com')->exists())->toBeTrue();
    DB::rollBack();
})->skip(fn () => ConcurrencyTestCase::engine() !== 'pgsql', 'MySQL answers "taken" here — the first test of this file.');

it('leaves a violation on another unique column the error it was, on the real engine too', function () use ($payload) {
    Schema::table('users', fn (Blueprint $table) => $table->unique('name'));
    DB::table('users')->insert(['name' => $payload['name'], 'email' => 'someone-else@example.com', 'password' => 'x']);

    expect(fn () => (new Register(User::class, 'email'))($payload))->toThrow(UniqueConstraintViolationException::class);
});
