<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Lukk\Actions\ChangePassword;
use Lukk\Tests\ConcurrencyTestCase;
use Lukk\Tests\Fixtures\User;

uses(ConcurrencyTestCase::class)->group('concurrency');

/*
 * A password change must not run the application's code inside a transaction of lukk's.
 *
 * On PostgreSQL a failed statement aborts the transaction it ran in, and `COMMIT` on an aborted
 * transaction silently becomes `ROLLBACK`. A revision of `ChangePassword` called `save()` under a row
 * lock, so a user-model observer that swallowed a failed query — a best-effort audit insert in a
 * try/catch — undid the password write while the request answered "password-changed", revoked the
 * other sessions and fired `PasswordChanged`. Only visible on the real engine: sqlite and MySQL carry
 * on after a failed statement.
 */

it('stores the new password even when a model observer swallows a failed query', function () {
    $user = User::factory()->create(['password' => Hash::make('password')]);

    User::updated(function () {
        try {
            DB::statement('select * from a_table_that_does_not_exist');
        } catch (Throwable) {
            // Best effort, as an audit trail usually is.
        }
    });

    app(ChangePassword::class)($user, 'password', 'brand-new-pass-1', null);

    $stored = (string) DB::table('users')->where('id', $user->id)->value('password');

    expect(Hash::check('brand-new-pass-1', $stored))->toBeTrue()
        ->and(Hash::check('password', $stored))->toBeFalse();
});
