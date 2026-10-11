<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\AttemptLogin;
use Lukk\Events\AccountLocked;
use Lukk\Tests\ConcurrencyTestCase;
use Lukk\Tests\Fixtures\User;

uses(ConcurrencyTestCase::class)->group('concurrency');

/**
 * Run `$work` in `$n` forked PHP processes released at the same instant, each on its OWN database
 * connection, and return what each returned. The only way to put real requests side by side from one
 * test: the race is between PHP processes holding separate sessions, which `pg_send_query`/
 * `MYSQLI_ASYNC` cannot model when the code under test is PHP rather than one SQL statement.
 *
 * The parent disconnects BEFORE forking — a child inheriting the open socket would share the server
 * session, and its exit would terminate the parent's — and children leave by SIGKILL, so no destructor
 * or PHPUnit shutdown hook runs twice.
 *
 * @return array<int, string>
 */
function inParallel(int $n, Closure $work): array
{
    DB::disconnect();
    $dir = sys_get_temp_dir().'/lukk-race-'.bin2hex(random_bytes(6));
    mkdir($dir);
    $start = microtime(true) + 0.5;
    $pids = [];

    for ($i = 0; $i < $n; $i++) {
        $pid = pcntl_fork();

        if ($pid === 0) {
            DB::reconnect();
            DB::select('select 1');   // connect before the start line, so the race is the work alone
            time_sleep_until($start);

            try {
                $result = (string) $work();
            } catch (Throwable $e) {
                $result = $e::class.': '.$e->getMessage();
            }

            file_put_contents("{$dir}/{$i}", $result);
            posix_kill(posix_getpid(), SIGKILL);
        }

        $pids[] = $pid;
    }

    foreach ($pids as $pid) {
        pcntl_waitpid($pid, $status);
    }

    $results = array_map(fn (int $i) => (string) @file_get_contents("{$dir}/{$i}"), range(0, $n - 1));
    array_map('unlink', glob("{$dir}/*") ?: []);
    rmdir($dir);
    DB::reconnect();

    return $results;
}

it('never verifies more than max_attempts concurrent guesses, and locks once', function () {
    // NIST SP 800-63B-4 §3.2.2. The lockout counts an attempt BEFORE verifying it and locks only once it
    // has FAILED (so a right password at the cap neither locks nor announces anything). The split must
    // not reopen check-then-act: the gate is still the post-increment count, taken under the row lock,
    // so of N simultaneous wrong passwords exactly `max_attempts` reach the hasher, the rest are 423,
    // and the account is locked — announced once, by whichever failure set it.
    if (! function_exists('pcntl_fork')) {
        test()->markTestSkipped('needs pcntl to run requests side by side');
    }

    (include __DIR__.'/../../database/lockout/0001_01_01_000000_create_lukk_lockouts_table.php')->up();
    config([
        'lukk.features.lockout' => true,
        'lukk.lockout.max_attempts' => 3,
        'lukk.lockout.release_after' => 0,
        'lukk.login_timebox_micros' => 0,
        'lukk.rate_limits.login.max_attempts' => 500,
        'lukk.rate_limits.login.account_max_attempts' => 500,
    ]);
    $user = User::factory()->create(['email' => 'victim@example.com']);
    $announced = sys_get_temp_dir().'/lukk-locked-'.bin2hex(random_bytes(6));
    Event::listen(AccountLocked::class, fn (AccountLocked $e) => file_put_contents($announced, $e->subject."\n", FILE_APPEND | LOCK_EX));

    $results = inParallel(8, function () {
        try {
            app(AttemptLogin::class)(Request::create('/auth/login', 'POST', ['email' => 'victim@example.com', 'password' => 'wrong']));

            return 'signed-in';
        } catch (ValidationException $e) {
            return (string) $e->status;
        }
    });

    $locks = array_count_values(array_filter(explode("\n", (string) @file_get_contents($announced))));
    @unlink($announced);

    $outcomes = array_count_values($results);
    ksort($outcomes);

    expect($outcomes)->toBe([422 => 3, 423 => 5])
        ->and(DB::table('lukk_lockouts')->where('subject', 'id:'.$user->getKey())->whereNotNull('locked_at')->exists())->toBeTrue()
        ->and($locks['id:'.$user->getKey()] ?? 0)->toBe(1);
});
