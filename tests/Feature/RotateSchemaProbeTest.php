<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Lukk\Tests\Fixtures\User;

uses()->group('refresh');

it('never asks the schema a question while holding the rotation row lock', function () {
    // `familyIsPinned()` refuses this exact cost in its own docblock — "two extra round trips, one
    // of them `information_schema`, on every ordinary human request" — and CLAUDE.md's rotate rule
    // is that no application code runs under the row lock, because lock duration, reverse-order
    // deadlocks and PostgreSQL's 25P02 all follow from it. A schema probe placed inside `persist()`
    // put two round trips between the locked read and the insert on every cold rotation, widening
    // precisely the window `tests/Concurrency/` exists to bound. The answer comes from the row the
    // non-locking pre-read already returned instead.
    // Through the LOGIN route, which stamps `amr` — `startSession()` alone stamps none, so the
    // conditional write short-circuits before the probe and the test would prove nothing.
    $user = User::factory()->create();
    $refresh = $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'password'])
        ->assertOk()->json('refresh_token');
    app('auth')->forgetGuards();

    // COLD, as a real request is. The sign-in above already answered the question, so leaving the
    // memo warm would make this test pass whatever `persist()` does — the first version of it did
    // exactly that. A php-fpm request that only refreshes starts with nothing memoized.
    // `instance()` registers in the container's INSTANCES, which `getBindings()` does not list, and
    // the key is built from the model's connection and table — guessing either wrong clears nothing
    // and the test proves nothing, which is exactly what two earlier versions of this line did. Read
    // the instances directly so the clear cannot silently miss.
    $instances = (new ReflectionProperty(app(), 'instances'));
    $all = $instances->getValue(app());
    $cleared = 0;
    foreach (array_keys($all) as $abstract) {
        if (str_starts_with((string) $abstract, 'lukk.schema.amr.')) {
            app()->forgetInstance($abstract);
            $cleared++;
        }
    }

    // The sign-in above must have memoized something, or this test is not starting cold.
    expect($cleared)->toBeGreaterThan(0);

    $insideTransaction = [];
    DB::listen(function ($query) use (&$insideTransaction) {
        if (DB::transactionLevel() > 0 && preg_match('/pragma|information_schema|sqlite_master|table_schema/i', $query->sql)) {
            $insideTransaction[] = $query->sql;
        }
    });

    $this->postJson('/auth/refresh', ['refresh_token' => $refresh])->assertOk();

    expect($insideTransaction)->toBe([]);
});
