<?php

declare(strict_types=1);

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Lukk\Actions\DisableTwoFactor;
use Lukk\Tests\Fixtures\User;

uses()->group('two-factor');

it('clamps the number of recovery codes to 1..100', function (int $asked, int $made) {
    expect(User::factory()->create()->generateRecoveryCodes($asked))->toHaveCount($made);
})->with([
    'zero' => [0, 1],
    'one' => [1, 1],
    'a hundred' => [100, 100],
    'over a hundred' => [150, 100],
]);

it('never spends a code twice through a model loaded before the first spend', function () {
    // Two requests each hold the user; the second one's copy still lists the code the first spent.
    $user = User::factory()->create();
    [$code] = $user->generateRecoveryCodes(2);
    $stale = User::query()->findOrFail($user->getKey());

    expect($user->useRecoveryCode($code))->toBeTrue()
        ->and($stale->useRecoveryCode($code))->toBeFalse();
});

it('keeps the stored set a JSON list after spending one', function () {
    $user = User::factory()->create();
    [$first] = $user->generateRecoveryCodes(3);

    $user->useRecoveryCode($first);

    expect(json_decode((string) $user->refresh()->two_factor_recovery_codes, true))->toBeList()->toHaveCount(2);
});

it('reads and spends a set stored as a JSON object', function () {
    // A set written by other code (or an older release) may be keyed rather than listed.
    $user = User::factory()->create();
    $user->forceFill(['two_factor_recovery_codes' => json_encode(['a' => Hash::make('one'), 'b' => Hash::make('two')])])->save();

    expect($user->recoveryCodesRemaining())->toBe(2)
        ->and($user->useRecoveryCode('two'))->toBeTrue()
        ->and($user->refresh()->recoveryCodesRemaining())->toBe(1);
});

it('clears the secret, the recovery codes and the confirmation when two-factor is disabled', function () {
    // All three: a secret left behind is a live second factor for whoever reads the row, and a
    // confirmation left behind turns 2FA back on the moment a secret is written again.
    $user = User::factory()->create();
    $user->forceFill([
        'two_factor_secret' => 'encrypted', 'two_factor_recovery_codes' => '[]', 'two_factor_confirmed_at' => now(),
    ])->save();

    app(DisableTwoFactor::class)($user);

    $user->refresh();
    expect($user->two_factor_secret)->toBeNull()
        ->and($user->two_factor_recovery_codes)->toBeNull()
        ->and($user->two_factor_confirmed_at)->toBeNull();
});

it('locks the user row inside the transaction before reading the codes', function () {
    // SQLite serialises writers, so a race cannot be staged here — and its grammar compiles no lock
    // at all. A grammar that records the lock it is asked for shows the request is made, under the
    // transaction that has to hold it.
    $connection = DB::connection();
    $grammar = new class($connection) extends SQLiteGrammar
    {
        /** @var array<int, array{0: string, 1: bool|string, 2: int}> */
        public array $locks = [];

        protected function compileLock(Builder $query, $value)
        {
            $this->locks[] = [(string) $query->from, $value, $query->getConnection()->transactionLevel()];

            return '';
        }
    };
    $connection->setQueryGrammar($grammar);
    $user = User::factory()->create();
    [$code] = $user->generateRecoveryCodes(1);
    $level = $connection->transactionLevel();

    $user->useRecoveryCode($code);

    expect($grammar->locks)->toBe([['users', true, $level + 1]]);
});

it('derives no hash while holding the lock on the user row', function () {
    // One bcrypt per stored code — up to a hundred — ran inside `lockForUpdate()`. A wrong guess
    // therefore held the user's row for seconds, stalling every other write to that account (a
    // sign-in's rehash, a profile save) for as long as someone kept guessing. Verifying needs no lock;
    // only removing the matched hash does.
    $user = User::factory()->create();
    [, $second] = $user->generateRecoveryCodes(3);

    $levels = [];
    $inner = app('hash')->driver();
    Hash::swap(new class($inner, $levels) implements Hasher
    {
        public function __construct(private readonly Hasher $inner, private array &$levels) {}

        public function info($hashedValue): array
        {
            return $this->inner->info($hashedValue);
        }

        public function make(#[SensitiveParameter] $value, array $options = []): string
        {
            return $this->inner->make($value, $options);
        }

        public function check(#[SensitiveParameter] $value, $hashedValue, array $options = []): bool
        {
            $this->levels[] = DB::transactionLevel();

            return $this->inner->check($value, $hashedValue, $options);
        }

        public function needsRehash($hashedValue, array $options = []): bool
        {
            return $this->inner->needsRehash($hashedValue, $options);
        }
    });

    // The suite may wrap each test in a transaction of its own, so compare with the level outside.
    $outside = DB::transactionLevel();

    expect($user->useRecoveryCode('wrong-guess'))->toBeFalse()
        ->and($user->useRecoveryCode($second))->toBeTrue()
        // Three for the miss, then two to find the second code: the search stops at the match.
        ->and($levels)->toHaveCount(5)
        ->and(array_values(array_unique($levels)))->toBe([$outside])
        ->and($user->refresh()->recoveryCodesRemaining())->toBe(2)
        ->and($user->useRecoveryCode($second))->toBeFalse();
});

it('takes no lock for a code that matches nothing', function () {
    // Every wrong guess would otherwise still lock the row, just more briefly.
    $user = User::factory()->create();
    $user->generateRecoveryCodes(2);
    $opened = 0;
    Event::listen(TransactionBeginning::class, function () use (&$opened) {
        $opened++;
    });

    expect($user->useRecoveryCode('wrong-guess'))->toBeFalse()
        ->and($opened)->toBe(0);
});
