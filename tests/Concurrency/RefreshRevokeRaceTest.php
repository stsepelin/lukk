<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Lukk\Actions\RotateRefreshToken;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Exceptions\InvalidRefreshToken;
use Lukk\Refresh\DatabaseRefreshTokenRepository;
use Lukk\Tests\ConcurrencyTestCase;
use Lukk\Tests\Fixtures\User;

uses(ConcurrencyTestCase::class)->group('concurrency');

/**
 * Fire a statement on a SECOND connection without waiting for it, so it can block on a lock the
 * test's own transaction holds. `pg_send_query` and `MYSQLI_ASYNC` are the only ways to do that
 * from one PHP process; a second PDO handle would just deadlock the test.
 */
function raceUpdate(string $engine, string $sql): callable
{
    if ($engine === 'pgsql') {
        $conn = pg_connect('host=127.0.0.1 port=55432 dbname=lukk user=lukk password=lukk');
        pg_send_query($conn, $sql);

        return function () use ($conn) {
            pg_get_result($conn);
            pg_close($conn);
        };
    }

    $conn = new mysqli('127.0.0.1', 'lukk', 'lukk', 'lukk', 33306);
    $conn->query($sql, MYSQLI_ASYNC);

    return function () use ($conn) {
        $r = [$conn];
        $e = [$conn];
        $rej = [$conn];
        mysqli::poll($r, $e, $rej, 5);
        $conn->reap_async_query();
        $conn->close();
    };
}

it('shows how a set-based family revoke behaves against an in-flight rotation', function (string $engine) {
    // Documents the engine behaviour the fix exists for, in raw SQL, so the reasoning is not
    // trapped in a commit message. PostgreSQL's UPDATE takes a statement-level snapshot before the
    // inserting transaction commits and, on unblocking, re-evaluates only the row it was waiting on
    // — so the successor is invisible and survives. InnoDB reads the latest version and catches it.
    DB::statement('DROP TABLE IF EXISTS race_probe');
    DB::statement($engine === 'pgsql'
        ? 'CREATE TABLE race_probe (id text primary key, family_id text, revoked_at timestamptz null)'
        : 'CREATE TABLE race_probe (id varchar(64) primary key, family_id varchar(64), revoked_at datetime null, index(family_id))');
    DB::statement("INSERT INTO race_probe VALUES ('parent', 'famX', null)");

    DB::beginTransaction();
    DB::select("SELECT * FROM race_probe WHERE id = 'parent' FOR UPDATE");

    $settle = raceUpdate($engine, "UPDATE race_probe SET revoked_at = now() WHERE family_id = 'famX' AND revoked_at IS NULL");
    usleep(300_000); // let it reach the lock

    DB::statement("INSERT INTO race_probe VALUES ('successor', 'famX', null)");
    DB::commit();
    $settle();
    usleep(200_000);

    $survived = DB::table('race_probe')->where('id', 'successor')->whereNull('revoked_at')->exists();

    expect($survived)->toBe($engine === 'pgsql');
})->with([[fn () => ConcurrencyTestCase::engine()]]);

it('never leaves a live token behind when a revoke races the rotation', function () {
    // The end-to-end version, through lukk's own rotate and revoke. The revoke is launched from
    // INSIDE the rotate transaction, at the instant the successor is persisted — the exact
    // interleaving that leaves an orphan on PostgreSQL.
    $engine = ConcurrencyTestCase::engine();
    $pair = User::factory()->create()->startSession();
    $familyId = (string) DB::table('refresh_tokens')->value('family_id');

    // A holder, because PHP cannot promote a by-reference constructor property.
    $race = new stdClass;
    $race->settle = null;

    app()->bind(RefreshTokenRepository::class, fn ($app) => new class($familyId, $engine, $race) extends DatabaseRefreshTokenRepository
    {
        public function __construct(private string $familyId, private string $engine, private stdClass $race)
        {
            parent::__construct(null);
        }

        public function persist(int|string $userId, string $familyId, ?string $previousId, string $tokenHash, int $expiresAt, ?string $scope = null): void
        {
            parent::persist($userId, $familyId, $previousId, $tokenHash, $expiresAt, $scope);

            // A concurrent logout starts here: the denylist first (as RevokeSession does), then the
            // set-based UPDATE, which blocks on the row lock this transaction holds.
            app(Denylist::class)->revokeFamily($this->familyId, 900);
            $this->race->settle = raceUpdate($this->engine, "UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = '{$this->familyId}' AND revoked_at IS NULL");
            usleep(300_000);
        }
    });

    expect(fn () => app(RotateRefreshToken::class)($pair->refreshToken))
        ->toThrow(InvalidRefreshToken::class);

    ($race->settle)();
    usleep(200_000);

    // The whole point: nothing in the family is still usable.
    expect(DB::table('refresh_tokens')->where('family_id', $familyId)->whereNull('revoked_at')->count())->toBe(0);
});

it('survives an abilities callback that poisons its own transaction', function (string $engine) {
    // PostgreSQL aborts the WHOLE transaction on any statement error: every subsequent command
    // fails with 25P02 ("current transaction is aborted") until a rollback. `abilitiesUsing` is
    // application code documented as hitting a permission store, so a callback that runs a bad
    // query and swallows the error — an entirely ordinary `try { } catch { return []; }` — would
    // poison lukk's rotate transaction from the inside if it ran within it. lukk's own COMMIT then
    // fails and rotation dies, for every user, until the app's bug is found.
    //
    // Invisible on sqlite (no such state) and on MySQL (statement-level rollback), which is why it
    // lives here. The fix is structural: the callback is resolved BEFORE the transaction opens, so
    // nothing but lukk's statements and pure crypto run inside it.
    if ($engine !== 'pgsql') {
        expect(true)->toBeTrue();   // 25P02 is PostgreSQL-specific

        return;
    }

    $pair = User::factory()->create()->startSession();

    Lukk\Lukk::abilitiesUsing(function () {
        try {
            DB::select('SELECT * FROM a_table_that_does_not_exist');
        } catch (Throwable) {
            // Swallowed, exactly as an app guarding against a flaky permission store would.
        }

        return ['orders.read'];
    });

    $before = DB::table('refresh_tokens')->count();
    $rotated = app(RotateRefreshToken::class)($pair->refreshToken);

    // Asserting the CALL succeeded proves nothing: PostgreSQL turns `COMMIT` on an aborted
    // transaction into a silent `ROLLBACK` and raises nothing, so lukk would hand back a perfectly
    // valid access token whose successor row was never written — and the client would find itself
    // logged out on its NEXT refresh, far from the cause. Assert the successor actually exists and
    // still rotates.
    expect(DB::table('refresh_tokens')->count())->toBe($before + 1);

    $again = app(RotateRefreshToken::class)($rotated->refreshToken);
    expect($again->accessToken)->toBeString();

    Lukk\Lukk::$abilitiesUsing = null;
})->with([[fn () => ConcurrencyTestCase::engine()]]);

it('does not hold the refresh row lock while application code runs', function (string $engine) {
    // The lock-duration half of the same problem: `abilitiesUsing` used to run under `FOR UPDATE`,
    // so a slow permission lookup serialized every refresh in the family behind it, and any callback
    // taking locks in the opposite order deadlocked against lukk. Assert the property directly —
    // the callback must not observe an open transaction.
    $pair = User::factory()->create()->startSession();
    $levels = [];

    Lukk\Lukk::abilitiesUsing(function () use (&$levels) {
        $levels[] = DB::transactionLevel();

        return ['orders.read'];
    });

    app(RotateRefreshToken::class)($pair->refreshToken);
    Lukk\Lukk::$abilitiesUsing = null;

    expect($levels)->not->toBeEmpty()->each->toBe(0);
})->with([[fn () => ConcurrencyTestCase::engine()]]);

it('does not hold the refresh row lock while ANY application callback runs', function (string $engine) {
    // `abilitiesUsing` was hoisted out of the transaction; `tokenClaimsUsing` was left behind,
    // because the issuer resolved it and the MINT moved inside the lock in the same change. Both are
    // consumer callbacks documented as reading a permission store, so both carry the same hazards: a
    // slow lookup serializes every refresh in the family, reverse lock order deadlocks against lukk,
    // and on PostgreSQL a swallowed SQL error leaves the transaction aborted — where COMMIT degrades
    // to a silent ROLLBACK and the client is logged out on its NEXT refresh.
    $pair = User::factory()->create()->startSession();
    $levels = [];

    Lukk\Lukk::abilitiesUsing(function () use (&$levels) {
        $levels['abilities'] = DB::transactionLevel();

        return ['orders.read'];
    });
    Lukk\Lukk::tokenClaimsUsing(function () use (&$levels) {
        $levels['claims'] = DB::transactionLevel();

        return ['org' => 1];
    });

    app(RotateRefreshToken::class)($pair->refreshToken);

    Lukk\Lukk::$abilitiesUsing = null;
    Lukk\Lukk::$tokenClaimsUsing = null;

    expect($levels)->toHaveKeys(['abilities', 'claims'])->each->toBe(0);
})->with([[fn () => ConcurrencyTestCase::engine()]]);
