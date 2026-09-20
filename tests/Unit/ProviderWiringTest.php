<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Lukk;
use Lukk\LukkServiceProvider;
use Lukk\Support\UnclaimedSessions;
use Lukk\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

function requestFrom(string $ip = '203.0.113.9'): Request
{
    return Request::create('/', 'POST', server: ['REMOTE_ADDR' => $ip]);
}

/** @return array<int, Limit> */
function limits(string $name, ?Request $request = null): array
{
    $out = app(RateLimiter::class)->limiter($name)($request ?? requestFrom());

    return is_array($out) ? $out : [$out];
}

function fresh(string $abstract): mixed
{
    app()->forgetInstance($abstract);

    return app($abstract);
}

describe('the default guard\'s named limiters', function () {
    $named = ['refresh' => 'lukk-refresh', 'passkeys' => 'lukk-passkeys', 'two_factor' => 'lukk-2fa',
        'email_verification' => 'lukk-email-verification', 'password_reset' => 'lukk-password-reset',
        'registration' => 'lukk-register', 'confirm' => 'lukk-confirm'];

    it('reads each one\'s limits as numbers from the strings env() delivers', function (string $key, string $name) {
        config(["lukk.rate_limits.{$key}" => ['max_attempts' => '7', 'decay_seconds' => '71']]);
        [$limit] = limits($name);

        expect([$limit->maxAttempts, $limit->decaySeconds])->toBe([7, 71]);
    })->with(array_map(null, array_keys($named), array_values($named)));

    it('falls back to 30 per 60s when a block is missing, or is not a block at all', function (string $key, string $name) {
        foreach ([null, 'garbage'] as $block) {
            config(["lukk.rate_limits.{$key}" => $block]);
            [$limit] = limits($name);

            expect([$limit->maxAttempts, $limit->decaySeconds])->toBe([30, 60]);
        }
    })->with(array_map(null, array_keys($named), array_values($named)));

    it('adds a per-user bucket on step-up and email verification, keyed to the guard and the user', function (string $name) {
        $user = User::factory()->create();
        $request = requestFrom();
        $request->setUserResolver(fn () => $user);

        $limits = limits($name, $request);

        expect($limits)->toHaveCount(2)
            ->and($limits[1]->key)->toBe($name.'|api|user|'.$user->getKey());
    })->with(['lukk-confirm', 'lukk-email-verification']);

    it('reads the login limit as numbers, and defaults it', function () {
        config(['lukk.rate_limits.login' => ['ip_max_attempts' => '6', 'decay_seconds' => '61']]);
        expect([limits('lukk-login')[0]->maxAttempts, limits('lukk-login')[0]->decaySeconds])->toBe([6, 61]);

        config(['lukk.rate_limits.login' => 'garbage']);
        expect([limits('lukk-login')[0]->maxAttempts, limits('lukk-login')[0]->decaySeconds])->toBe([30, 60]);
    });

    it('keys the claim limiter on the refresh limits, and survives a refresh block that is not one', function () {
        config(['lukk.rate_limits.refresh' => 'garbage']);
        expect([limits('lukk-claim')[0]->maxAttempts, limits('lukk-claim')[0]->decaySeconds])->toBe([30, 60]);
    });
});

it('builds the TOTP provider from the configured issuer and a clamped window', function () {
    config(['lukk.two_factor' => ['issuer' => 'Example Shop', 'window' => '0']]);
    $totp = fresh(TwoFactorProvider::class);
    $secret = $totp->generateSecret();
    $engine = app(Google2FA::class);

    expect($totp->otpauthUri('ada@example.test', $secret))->toContain('issuer=Example%20Shop')
        // `'0'` from env is a number: exactly the current step, not the previous one.
        ->and($totp->verify($secret, $engine->oathTotp($secret, $engine->getTimestamp() - 1)))->toBeFalse();

    config(['lukk.two_factor' => ['window' => 25]]);
    $totp = fresh(TwoFactorProvider::class);
    $secret = $totp->generateSecret();
    expect($totp->verify($secret, $engine->oathTotp($secret, $engine->getTimestamp() - 10)))->toBeTrue()
        ->and($totp->verify($secret, $engine->oathTotp($secret, $engine->getTimestamp() - 11)))->toBeFalse();

    config(['lukk.two_factor' => ['window' => -3]]);
    $totp = fresh(TwoFactorProvider::class);
    $secret = $totp->generateSecret();
    expect($totp->verify($secret, $engine->oathTotp($secret, $engine->getTimestamp())))->toBeTrue();
});

it('defaults the TOTP window to one step each way, and survives a block that is not one', function () {
    $engine = app(Google2FA::class);

    foreach ([null, 'garbage'] as $block) {
        config(['lukk.two_factor' => $block]);
        $totp = fresh(TwoFactorProvider::class);
        $secret = $totp->generateSecret();

        expect($totp->verify($secret, $engine->oathTotp($secret, $engine->getTimestamp() - 1)))->toBeTrue()
            ->and($totp->verify($secret, $engine->oathTotp($secret, $engine->getTimestamp() - 2)))->toBeFalse()
            ->and($totp->otpauthUri('ada@example.test', $secret))->toContain('issuer='.rawurlencode((string) config('app.name')));
    }
});

it('reads a non-numeric TOTP window as 0, not as the widest one', function (mixed $window) {
    // PHP 8 compares an int with a non-numeric string as strings, so without the cast
    // `min(10, 'abc')` is 10: a typo would admit 21 codes instead of one.
    config(['lukk.two_factor' => ['window' => $window]]);
    $totp = fresh(TwoFactorProvider::class);
    $secret = $totp->generateSecret();
    $engine = app(Google2FA::class);

    expect($totp->verify($secret, $engine->oathTotp($secret, $engine->getTimestamp())))->toBeTrue()
        ->and($totp->verify($secret, $engine->oathTotp($secret, $engine->getTimestamp() - 1)))->toBeFalse();
})->with([
    'a typo' => ['abc'],
    'an array' => [[]],
]);

it('reads a passkeys or lockout block that is not an array as missing', function () {
    config(['lukk.passkeys' => 'garbage']);
    expect(fn () => fresh(WebAuthnCeremony::class))->toThrow(InvalidArgumentException::class, 'Passkeys require lukk.passkeys.rp_id');

    config(['lukk.lockout' => 'garbage']);
    expect(app(LockoutRepository::class)->maxAttempts())->toBe(100);
});

it('keeps lockout off when the feature flag is missing — it is opt-in', function () {
    $lukk = (array) config('lukk');
    unset($lukk['features']['lockout']);
    config()->set('lukk', $lukk);
    $user = User::factory()->create();

    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'wrong'])->assertUnprocessable();

    expect(DB::table('lukk_lockouts')->count())->toBe(0);
});

it('keeps revocations in the configured store, and refuses one that cannot hold them in production', function () {
    config(['lukk.denylist_store' => 'nope']);
    expect(fn () => fresh(UnclaimedSessions::class))->toThrow(InvalidArgumentException::class, 'Cache store [nope] is not defined');

    config(['lukk.denylist_store' => 'array']);
    app()->detectEnvironment(fn () => 'production');
    try {
        expect(fn () => fresh(UnclaimedSessions::class))->toThrow(RuntimeException::class, 'lukk cannot use the [ArrayStore] cache store');
    } finally {
        app()->detectEnvironment(fn () => 'testing');
    }
});

it('resolves an extra guard with no provider of its own to lukk.user_provider, and the default guard by name', function () {
    $provider = app()->getProvider(LukkServiceProvider::class);
    $for = fn (string $guard) => (fn () => $this->userProviderFor($guard))->call($provider);
    config(['auth.providers.others' => ['driver' => 'eloquent', 'model' => Lukk\Tests\Fixtures\Admin::class]]);

    config(['lukk.user_provider' => 'others', 'auth.guards.extra' => ['driver' => 'lukk-jwt']]);
    expect($for('extra')->getModel())->toBe(Lukk\Tests\Fixtures\Admin::class);

    // Renamed default guard: still the default branch, so `auth.guards.members.provider` is not consulted.
    config(['lukk.guard' => 'members', 'auth.guards.members' => ['driver' => 'lukk-jwt', 'provider' => 'users']]);
    expect($for('members')->getModel())->toBe(Lukk\Tests\Fixtures\Admin::class);
});

it('refuses a numeric guard name at boot, naming it', function () {
    config(['lukk.guards' => [2 => ['audience' => ['https://two.test']]]]);

    expect(fn () => Lukk::assertGuardsIsolated())->toThrow(RuntimeException::class, 'lukk guard [2] has a numeric name');
});

it('refuses a numeric default guard name too', function () {
    // `auth.guards` keys it as an int as well, so it failed later with a misleading "no config
    // block" error instead.
    config(['lukk.guard' => '2', 'auth.guards.2' => ['driver' => 'lukk-jwt', 'provider' => 'users']]);

    expect(fn () => Lukk::assertGuardsIsolated())->toThrow(RuntimeException::class, 'lukk guard [2] has a numeric name');
});

it('says so when lukk.guards lists names instead of mapping them to blocks', function () {
    config(['lukk.guards' => ['admin']]);

    expect(fn () => Lukk::assertGuardsIsolated())
        ->toThrow(RuntimeException::class, "lukk.guards maps guard names to config blocks, not a list of names: write ['admin' => [...]] rather than ['admin'].");
});

it('refuses a lukk.guards that is a truthy scalar', function (mixed $guards, string $type) {
    config(['lukk.guards' => $guards]);

    expect(fn () => Lukk::assertGuardsIsolated())
        ->toThrow(RuntimeException::class, "lukk.guards must map each guard name to its config block, e.g. ['admin' => [...]]; got {$type}.");
})->with([
    'a string' => ['admin', 'string'],
    'true' => [true, 'bool'],
]);

it('reads a falsy lukk.guards as "no extra guards", and boots', function (mixed $guards) {
    // A verify-only service with `guards => false` booted before the numeric-name check existed:
    // `(array) false` is `[0 => false]`, and key 0 must not read as a guard named "0".
    config(['lukk.guards' => $guards]);

    expectNoThrow(fn () => Lukk::assertGuardsIsolated());
    // The routes too: they mounted a guard named 0 and died on a TypeError.
    expectNoThrow(fn () => require dirname(__DIR__, 2).'/src/routes/api.php');
    expect(Lukk::guardNames())->toBe(['api']);
})->with([
    'false' => [false],
    'an empty string' => [''],
]);
