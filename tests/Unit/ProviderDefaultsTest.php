<?php

declare(strict_types=1);

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Support\Arr;
use Illuminate\Support\ServiceProvider;
use Lukk\Actions\EnableTwoFactor;
use Lukk\Actions\RegenerateRecoveryCodes;
use Lukk\Actions\VerifyTwoFactorChallenge;
use Lukk\Auth\LoginRateLimiter;
use Lukk\LukkServiceProvider;
use Lukk\Passkeys\PasskeyChallengeStore;
use Lukk\Tests\Fixtures\User;

/*
 * What the service provider hands the things it builds.
 *
 * The flows are tested where they live, and from there the provider is nearly invisible: a default
 * that drifts from 5 attempts to 6, a configured value that is ignored for the default, a publish group
 * that stops existing — each leaves every flow working. Measured on 2026-11-14 with a mutation run that
 * really ran the tests: 58 such changes to this one file survived the whole suite.
 *
 * Config values are given as STRINGS where they are numbers, because that is what `env()` returns for
 * anything set in a `.env` file, and the constructors they reach are strictly typed.
 */

/** A constructor-promoted private property of a resolved object. */
function wired(object $object, string $property): mixed
{
    return (fn () => $this->{$property})->call($object);
}

/** Strip keys from the `lukk` block, as a config cached before they existed leaves it. */
function withoutKeys(string ...$keys): void
{
    $lukk = config('lukk');

    foreach ($keys as $key) {
        Arr::forget($lukk, $key);
    }

    config(['lukk' => $lukk]);
}

it('builds the login limiter from the configured caps, read as numbers', function () {
    config(['lukk.rate_limits.login' => ['max_attempts' => '3', 'decay_seconds' => '90', 'account_max_attempts' => '7']]);

    $limiter = app(LoginRateLimiter::class);

    expect([wired($limiter, 'maxAttempts'), wired($limiter, 'decaySeconds'), wired($limiter, 'accountMaxAttempts')])->toBe([3, 90, 7]);
});

it('builds the login limiter from the shipped caps when none are configured', function () {
    withoutKeys('rate_limits.login');

    $limiter = app(LoginRateLimiter::class);
    $shipped = (require __DIR__.'/../../config/lukk.php')['rate_limits']['login'];

    expect([wired($limiter, 'maxAttempts'), wired($limiter, 'decaySeconds'), wired($limiter, 'accountMaxAttempts')])
        ->toBe([5, 60, 20])
        ->toBe([$shipped['max_attempts'], $shipped['decay_seconds'], $shipped['account_max_attempts']]);
});

it('builds the two-factor challenge from the configured caps, read as numbers', function () {
    config(['lukk.rate_limits.two_factor' => ['max_attempts' => '2', 'decay_seconds' => '45']]);

    $verify = app(VerifyTwoFactorChallenge::class);

    expect([wired($verify, 'maxAttempts'), wired($verify, 'decaySeconds')])->toBe([2, 45]);
});

it('builds the two-factor challenge from the shipped caps when none are configured', function () {
    withoutKeys('rate_limits.two_factor');

    $verify = app(VerifyTwoFactorChallenge::class);
    $shipped = (require __DIR__.'/../../config/lukk.php')['rate_limits']['two_factor'];

    expect([wired($verify, 'maxAttempts'), wired($verify, 'decaySeconds')])
        ->toBe([5, 60])
        ->toBe([$shipped['max_attempts'], $shipped['decay_seconds']]);
});

it('hands out the configured number of recovery codes, on enrolment and on regeneration', function () {
    config(['lukk.two_factor.recovery_codes' => '4']);

    expect(wired(app(EnableTwoFactor::class), 'recoveryCodes'))->toBe(4)
        ->and(wired(app(RegenerateRecoveryCodes::class), 'recoveryCodes'))->toBe(4);
});

it('keeps a passkey challenge for the configured ceremony plus the transit margin, to the second', function (?string $configured, int $kept) {
    $configured === null ? withoutKeys('passkeys.challenge_ttl') : config(['lukk.passkeys.challenge_ttl' => $configured]);
    app()->forgetInstance(PasskeyChallengeStore::class);
    $this->freezeSecond();

    $store = app(PasskeyChallengeStore::class);
    $early = $store->putForCeremony('EARLY');
    $late = $store->putForCeremony('LATE');

    $this->travel($kept - 1)->seconds();
    expect($store->pullForCeremony($early))->toBe('EARLY');

    $this->travel(1)->seconds();
    expect($store->pullForCeremony($late))->toBeNull();
})->with([
    'configured' => ['120', 150],
    'the shipped default' => [null, 330],
]);

it('signs the verification link for the configured number of minutes', function (?string $configured, int $minutes) {
    $configured === null ? withoutKeys('email_verification.expire') : config(['lukk.email_verification.expire' => $configured]);
    $this->freezeSecond();

    $url = (VerifyEmail::$createUrlCallback)(User::factory()->create());
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    expect((int) $query['expires'])->toBe(now()->addMinutes($minutes)->getTimestamp());
})->with([
    'configured' => ['30', 30],
    'the shipped default' => [null, 60],
]);

it('refuses to boot guards that are not isolated', function () {
    // `Lukk::assertGuardsIsolated()` is tested on its own; this is that boot actually asks.
    config(['auth.guards.api' => ['driver' => 'lukk-jwt', 'provider' => 'elsewhere'], 'lukk.user_provider' => 'users']);

    expect(fn () => (new LukkServiceProvider(app()))->boot())->toThrow(RuntimeException::class, '[elsewhere] provider');
});

it('points a notification at lukk only when its feature is switched on', function (string $feature, string $notification) {
    // An unset flag is not a decision to take over the host application's own verification or reset
    // emails — these default OFF, unlike the routes that default on.
    $boot = function (mixed $flag) use ($feature, $notification) {
        $notification::$createUrlCallback = null;
        config(["lukk.features.{$feature}" => $flag]);
        (new LukkServiceProvider(app()))->boot();

        return $notification::$createUrlCallback;
    };

    expect($boot(null))->toBeNull()
        ->and($boot(false))->toBeNull()
        ->and($boot(true))->toBeInstanceOf(Closure::class);
})->with([
    ['email_verification', VerifyEmail::class],
    ['password_reset', ResetPassword::class],
]);

it('publishes its config and each migration set under a group of its own', function (string $group, string $from, string $to) {
    $paths = ServiceProvider::pathsToPublish(LukkServiceProvider::class, $group);

    expect($paths)->toHaveCount(1)
        ->and(realpath((string) array_key_first($paths)))->toBe(realpath(__DIR__.'/../../'.$from))
        ->and(realpath(__DIR__.'/../../'.$from))->not->toBeFalse()
        ->and(array_values($paths))->toBe([$to === 'config' ? config_path('lukk.php') : database_path('migrations')]);
})->with([
    ['lukk-config', 'config/lukk.php', 'config'],
    ['lukk-migrations', 'database/migrations', 'migrations'],
    ['lukk-two-factor-migrations', 'database/two-factor', 'migrations'],
    ['lukk-passkey-migrations', 'database/passkeys', 'migrations'],
    ['lukk-lockout-migrations', 'database/lockout', 'migrations'],
]);

it('publishes nothing outside those groups', function () {
    // Every path it offers belongs to exactly one named group: an ungrouped one is copied by a bare
    // `vendor:publish --provider`, optional schema included.
    $grouped = collect(['lukk-config', 'lukk-migrations', 'lukk-two-factor-migrations', 'lukk-passkey-migrations', 'lukk-lockout-migrations'])
        ->flatMap(fn (string $group) => ServiceProvider::pathsToPublish(LukkServiceProvider::class, $group));

    expect(ServiceProvider::pathsToPublish(LukkServiceProvider::class))->toHaveCount(5)->toBe($grouped->all());
});
