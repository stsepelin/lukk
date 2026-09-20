<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Lukk\Contracts\LockoutRepository;
use Lukk\Models\Lockout;
use Lukk\Tests\Fixtures\User;

beforeEach(fn () => config([
    'lukk.features.lockout' => true,
    'lukk.lockout.max_attempts' => 1,
    'lukk.lockout.release_after' => 0,
]));

function lockLogin(string $subject, string $guard = 'api'): void
{
    app(LockoutRepository::class)->recordFailure('login', $subject, $guard);
}

it('refuses an unknown purpose before looking anything up', function () {
    command('lukk:release', ['subject' => 'ada@example.test', '--purpose' => 'sessions'])
        ->expectsOutputToContain('--purpose must be "login", "two_factor" or "confirm".')
        ->doesntExpectOutputToContain('No sessions lock found')
        ->assertFailed();
});

it('names what it looked for when there is nothing to release', function () {
    command('lukk:release', ['subject' => 'nobody@example.test'])
        ->expectsOutputToContain('No login lock found for [nobody@example.test] on guard [api].')
        ->assertFailed();
});

it('names what it released', function () {
    $user = User::factory()->create(['email' => 'ada@example.test']);
    lockLogin('id:'.$user->getKey());

    command('lukk:release', ['subject' => 'ada@example.test'])
        ->expectsOutputToContain('Released the login lock on [ada@example.test].')
        ->assertSuccessful();

    expect(Lockout::query()->exists())->toBeFalse();
});

it('finds an account stored with capitals from the address as pasted', function () {
    // SQLite and PostgreSQL compare binary, so only the trimmed-as-pasted lookup matches a stored
    // `Ada@Example.test`; the normalized fallback is lower-cased and would miss it.
    $user = User::factory()->create(['email' => 'Ada@Example.test']);
    lockLogin('id:'.$user->getKey());

    command('lukk:release', ['subject' => '  Ada@Example.test '])->assertSuccessful();
});

it('looks the account up through the provider sign-in uses for the default guard', function () {
    // The default guard's users come from `lukk.user_provider`. Reading `auth.guards.api.provider`
    // instead looked in another table (here: none) and reported no lock for one that exists.
    $user = User::factory()->create(['email' => 'ada@example.test']);
    lockLogin('id:'.$user->getKey());
    config(['auth.guards.api.provider' => 'missing']);

    command('lukk:release', ['subject' => 'ada@example.test'])->assertSuccessful();
});

it('falls back to the address bucket when the guard\'s provider is not configured', function () {
    config(['auth.guards.ghost' => ['driver' => 'lukk-jwt', 'provider' => 'missing']]);
    lockLogin('idn:ada@example.test', 'ghost');

    command('lukk:release', ['subject' => 'Ada@Example.test', '--guard' => 'ghost'])->assertSuccessful();
});

it('keys the lookup on email when lukk.username is null', function () {
    $user = User::factory()->create(['email' => 'ada@example.test']);
    lockLogin('id:'.$user->getKey());
    config(['lukk.username' => null]);

    command('lukk:release', ['subject' => 'ada@example.test'])->assertSuccessful();
});

it('looks the account up by the configured username column', function () {
    Schema::table('users', fn (Blueprint $table) => $table->string('username')->nullable());
    config(['lukk.username' => 'username']);
    $user = User::factory()->create(['username' => 'ada']);
    lockLogin('id:'.$user->getKey());

    command('lukk:release', ['subject' => 'ada'])->assertSuccessful();
});

it('trims the purpose and subject an operator pastes', function () {
    lockLogin('idn:nobody@example.test');

    command('lukk:release', ['subject' => '  nobody@example.test ', '--purpose' => ' login '])
        ->expectsOutputToContain('Released the login lock on [nobody@example.test].')
        ->assertSuccessful();
});

it('reads a numeric subject, and treats one that is not a value as empty', function () {
    command('lukk:release', ['subject' => 42, '--purpose' => 'confirm'])
        ->expectsOutputToContain('No confirm lock found for [42] on guard [api].')
        ->assertFailed();

    command('lukk:release', ['subject' => ['a'], '--purpose' => 'confirm'])
        ->expectsOutputToContain('No confirm lock found for [] on guard [api].')
        ->assertFailed();
});
