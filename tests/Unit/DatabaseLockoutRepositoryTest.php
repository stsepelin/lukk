<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Lukk\Events\AccountReleased;
use Lukk\Lockout\DatabaseLockoutRepository;
use Lukk\Models\Lockout;

uses()->group('lockout');

beforeEach(fn () => $this->freezeSecond());

function lockouts(int $max = 2, int $after = 30): DatabaseLockoutRepository
{
    return new DatabaseLockoutRepository($max, $after);
}

function lockSubject(DatabaseLockoutRepository $repo, string $subject = 'ada', ?string $guard = null): void
{
    for ($i = 0; $i < $repo->maxAttempts(); $i++) {
        $repo->recordFailure('login', $subject, $guard);
    }
}

it('counts nothing, releases nothing and reports nothing for an empty subject', function () {
    // One empty subject would be ONE bucket for every caller — a lock on the whole application.
    $repo = lockouts();

    expect($repo->recordFailure('login', '', null))->toBe(0)
        ->and($repo->release('login', '', null))->toBe(0)
        ->and($repo->availableIn('login', '', null))->toBeNull()
        ->and(DB::table('lukk_lockouts')->count())->toBe(0);
});

it('keeps one counter per guard, and finds it again', function () {
    $repo = lockouts(5);
    $repo->recordFailure('login', 'ada', 'admin');

    expect($repo->recordFailure('login', 'ada', 'admin'))->toBe(2)
        ->and(DB::table('lukk_lockouts')->where('guard', 'admin')->value('attempts'))->toBe(2);
});

it('reads an existing counter without trying to insert another', function () {
    $repo = lockouts(5);
    $repo->recordFailure('login', 'ada', null);
    // `beforeExecuting`, not `listen`: an INSERT that fails on the unique index never reaches a listener.
    $inserts = 0;
    DB::beforeExecuting(function (string $sql) use (&$inserts) {
        $inserts += (int) str_starts_with(strtolower($sql), 'insert');
    });

    $repo->recordFailure('login', 'ada', null);

    expect($inserts)->toBe(0);
});

it('releases only what is there, and announces only a real release', function () {
    Event::fake([AccountReleased::class]);
    $repo = lockouts();
    $queries = 0;
    DB::listen(function () use (&$queries) {
        $queries++;
    });

    expect($repo->release('login', 'nobody', null))->toBe(0);
    // One existence check on the hot path — no DELETE, which gap-locks under InnoDB.
    expect($queries)->toBeLessThanOrEqual(2);
    Event::assertNotDispatched(AccountReleased::class);

    lockSubject($repo);
    expect($repo->release('login', 'ada', null))->toBe(1);
    Event::assertDispatchedTimes(AccountReleased::class, 1);
});

it('counts down to the release, and never below zero', function () {
    $repo = lockouts(2, 30);
    lockSubject($repo);

    expect($repo->availableIn('login', 'ada', null))->toBe(30);
    $this->travel(10)->seconds();
    expect($repo->availableIn('login', 'ada', null))->toBe(20);
    $this->travel(60)->seconds();
    expect($repo->availableIn('login', 'ada', null))->toBe(0);
});

it('counts a lock stamped ahead of this clock by its distance, not as extra time', function () {
    // Database and application clocks disagree; the distance is what matters, in either direction.
    $repo = lockouts(2, 30);
    lockSubject($repo);
    DB::table('lukk_lockouts')->update(['locked_at' => Carbon::now()->addSeconds(10)]);

    expect($repo->availableIn('login', 'ada', null))->toBe(20);
});

it('reports nothing for a subject that never failed, and for one that failed but is not locked', function () {
    $repo = lockouts(5, 30);
    expect($repo->availableIn('login', 'never', null))->toBeNull();

    $repo->recordFailure('login', 'once', null);
    expect($repo->availableIn('login', 'once', null))->toBeNull();
});

it('lets a one-second release actually release', function () {
    $repo = lockouts(2, 1);
    lockSubject($repo);
    expect($repo->locked('login', 'ada', null))->toBeTrue();

    $this->travel(2)->seconds();
    expect($repo->locked('login', 'ada', null))->toBeFalse();
});

it('forgets and summarises only the named guard, reading no guard as the default one', function () {
    $repo = lockouts(5);
    $repo->recordFailure('login', 'ada', null);
    $repo->recordFailure('login', 'ada', 'admin');

    expect($repo->summariesForSubjects(['ada'], null))->toHaveCount(1)
        ->and($repo->forget(['ada'], null))->toBe(1)
        ->and(DB::table('lukk_lockouts')->where('guard', 'admin')->count())->toBe(1);
});

it('never reaches a row with an empty subject, whatever is asked for', function () {
    DB::table('lukk_lockouts')->insert(['id' => (string) Str::ulid(), 'purpose' => 'login', 'subject' => '', 'guard' => '', 'attempts' => 3, 'created_at' => now(), 'updated_at' => now()]);
    $repo = lockouts();

    expect($repo->summariesForSubjects(['', 'x'], null))->toBe([])
        ->and($repo->forget(['', 'x'], null))->toBe(0)
        ->and($repo->forget([], null))->toBe(0)
        ->and(DB::table('lukk_lockouts')->count())->toBe(1);
});

it('summarises a row whose timestamps were never written', function () {
    DB::table('lukk_lockouts')->insert(['id' => (string) Str::ulid(), 'purpose' => 'login', 'subject' => 'ada', 'guard' => '', 'attempts' => 1]);

    expect(lockouts()->summariesForSubjects(['ada'], null))->toBe([
        ['purpose' => 'login', 'attempts' => 1, 'locked_at' => null, 'first_failed_at' => null, 'last_failed_at' => null],
    ]);
});

it('prunes stale counters and spent locks, never a held one, and never anything younger than a day', function () {
    $repo = lockouts(5, 30);
    $repo->recordFailure('login', 'stale', null);
    $repo->recordFailure('login', 'fresh', null);
    DB::table('lukk_lockouts')->where('subject', 'stale')->update(['updated_at' => Carbon::now()->subDays(40)]);
    DB::table('lukk_lockouts')->where('subject', 'fresh')->update(['updated_at' => Carbon::now()->subDays(2)]);

    expect($repo->prune(30))->toBe(1)
        ->and(DB::table('lukk_lockouts')->pluck('subject')->all())->toBe(['fresh']);

    // A floor of one day: `0` does not mean "everything".
    DB::table('lukk_lockouts')->where('subject', 'fresh')->update(['updated_at' => Carbon::now()->subHours(12)]);
    expect($repo->prune(0))->toBe(0);
});

it('prunes a lock once a one-second release has passed, and not a fresh one', function () {
    $repo = lockouts(2, 1);
    lockSubject($repo, 'old');
    $this->travel(5)->seconds();
    lockSubject($repo, 'recent');

    expect($repo->prune(30))->toBe(1)
        ->and(DB::table('lukk_lockouts')->pluck('subject')->all())->toBe(['recent']);
});

it('never prunes a held lock when release is manual-only', function () {
    $repo = lockouts(2, 0);
    lockSubject($repo);
    $this->travel(400)->days();

    expect($repo->prune(30))->toBe(0);
});

it('answers every call without the table, instead of a SQL error', function () {
    Schema::drop('lukk_lockouts');
    $repo = lockouts();

    expect($repo->recordFailure('login', 'ada', null))->toBe(0)
        ->and($repo->release('login', 'ada', null))->toBe(0)
        ->and($repo->forget(['ada'], null))->toBe(0)
        ->and($repo->summariesForSubjects(['ada'], null))->toBe([])
        ->and($repo->prune(30))->toBe(0);
});

it('does not announce a release another request already made', function () {
    // The row is there when this release checks, and gone by the time it deletes — a concurrent release
    // won. Only the one that deleted it announces it.
    Event::fake([AccountReleased::class]);
    $repo = lockouts();
    lockSubject($repo);
    DB::listen(function ($query) {
        // The row-existence check, not the table check `usable()` runs first.
        if (str_contains($query->sql, 'exists(select * from "lukk_lockouts"')) {
            DB::table('lukk_lockouts')->delete();
        }
    });

    expect($repo->release('login', 'ada', null))->toBe(0);
    Event::assertNotDispatched(AccountReleased::class);
});

it('forgets an empty list without touching the table', function () {
    $deletes = 0;
    DB::beforeExecuting(function (string $sql) use (&$deletes) {
        $deletes += (int) str_starts_with(strtolower($sql), 'delete');
    });

    expect(lockouts()->forget([], null))->toBe(0)
        ->and($deletes)->toBe(0);
});

it('prunes a counter older than the one-day minimum', function () {
    $repo = lockouts(5, 30);
    $repo->recordFailure('login', 'ada', null);
    DB::table('lukk_lockouts')->update(['updated_at' => Carbon::now()->subHours(36)]);

    expect($repo->prune(1))->toBe(1);
});

it('reads the attempt count as an integer whatever the driver hands back', function () {
    // Some PDO drivers return integer columns as strings, and the cap is compared with `>=`.
    expect((new Lockout)->forceFill(['attempts' => '3'])->attempts)->toBe(3);
});
