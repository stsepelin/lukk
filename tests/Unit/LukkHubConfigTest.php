<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Lukk\Lukk;
use Lukk\Support\VerifiedToken;
use Lukk\Tests\Fixtures\User;

/** Two lukk-jwt guards beside the default, on the given path/domain/audience shapes. */
function twoGuards(array $admin, array $ops): void
{
    config([
        'auth.guards.admin' => ['driver' => 'lukk-jwt', 'provider' => 'users'],
        'auth.guards.ops' => ['driver' => 'lukk-jwt', 'provider' => 'users'],
        'lukk.guards' => [
            'admin' => ['audience' => ['https://admin.test'], 'path' => 'staff', ...$admin],
            'ops' => ['audience' => ['https://ops.test'], 'path' => 'staff', ...$ops],
        ],
    ]);
}

it('lists every guard name once, in order, from any config shape', function () {
    config(['lukk.guard' => 'web2', 'lukk.guards' => ['admin' => [], 'web2' => [], 'ops' => []]]);
    expect(Lukk::guardNames())->toBe(['web2', 'admin', 'ops']);

    config(['lukk.guards' => null]);
    expect(Lukk::guardNames())->toBe(['web2']);

    config(['lukk' => null]);
    expect(Lukk::guardNames())->toBe(['api']);
});

it('reads a guard whose block is null, or not a block at all, as the defaults — not a TypeError', function () {
    foreach ([null, 'garbage'] as $block) {
        config(['lukk.guards' => ['stale' => $block], 'lukk.access_ttl' => 123]);

        expect(Lukk::guardConfig('stale')['access_ttl'])->toBe(123);
    }
});

it('reports abilities in use only when the flag is on, reading a string flag from env as a boolean', function () {
    $lukk = (array) config('lukk');
    unset($lukk['features']['abilities']);
    config()->set('lukk', $lukk);
    expect(Lukk::usesAbilities())->toBeFalse();

    config(['lukk.features.abilities' => '1']);
    expect(Lukk::usesAbilities())->toBeTrue();
});

it('boots guards that share a path on distinct domains', function () {
    twoGuards(['domain' => 'admin.test'], ['domain' => 'ops.test']);

    expectNoThrow(fn () => Lukk::assertGuardsIsolated());
});

it('refuses guards that can serve the same host and path', function (?string $admin, ?string $ops) {
    // A null or empty domain is a wildcard: it shadows the other guard on every host.
    twoGuards(['domain' => $admin], ['domain' => $ops]);

    expect(fn () => Lukk::assertGuardsIsolated())
        ->toThrow(RuntimeException::class, 'lukk guards [admin] and [ops] can serve the same host and path');
})->with([
    'the same domain' => ['admin.test', 'admin.test'],
    'the first a wildcard' => [null, 'ops.test'],
    'the second a wildcard' => ['admin.test', null],
    'an empty domain is a wildcard too' => ['', 'ops.test'],
]);

it('reads a numeric domain and its string form as the same host', function () {
    // The domains are compared with `===`, so without the cast 5 and '5' would not collide.
    twoGuards(['domain' => 5], ['domain' => '5']);

    expect(fn () => Lukk::assertGuardsIsolated())
        ->toThrow(RuntimeException::class, 'lukk guards [admin] and [ops] can serve the same host and path');
});

it('accepts an audience given as a single string, and ignores an empty entry', function () {
    // `env()` hands a single audience over as a string; an empty entry is an unset env in a list, and must
    // not read as a shared '' audience between the two guards.
    twoGuards(['domain' => 'admin.test', 'audience' => 'https://admin.test'], ['domain' => 'ops.test', 'audience' => ['', 'https://ops.test']]);
    config(['lukk.guards.admin.audience' => ['', 'https://admin.test']]);

    expectNoThrow(fn () => Lukk::assertGuardsIsolated());

    config(['lukk.guards.admin.audience' => 'https://admin.test']);
    expectNoThrow(fn () => Lukk::assertGuardsIsolated());
});

it('says exactly how a driver guard with no config block would leak', function () {
    config(['auth.guards.stray' => ['driver' => 'lukk-jwt', 'provider' => 'users']]);

    expect(fn () => Lukk::assertGuardsIsolated())->toThrow(RuntimeException::class,
        'lukk guard [stray] uses the lukk-jwt driver but has no `lukk.guards.stray` config block, so it would inherit the [api] guard\'s secret AND audience — and a token minted for [api] would authenticate as a [stray] user with the same id. Give it its own block with a distinct `audience` (and ideally its own `secret`), or drop the guard from config/auth.php.');
});

it('acts as the user on the named guard, with a pinned token naming them', function () {
    $user = User::factory()->create();

    Lukk::actingAs($user, 'api', ['orders.read']);

    $token = VerifiedToken::current(Request::create('/'), 'api');
    expect(app('auth')->getDefaultDriver())->toBe('api')
        ->and($token?->claims)->toEqual((object) ['sub' => (string) $user->getKey(), 'scope' => 'orders.read', 'pin' => true])
        ->and($token?->claims->sub)->toBeString();
});

it('names the default guard api when lukk.guard is unset, null, empty or not a value', function (mixed $guard) {
    config(['lukk.guard' => $guard]);

    expect(Lukk::defaultGuard())->toBe('api');
})->with([
    'null' => [null],
    'an empty env line' => [''],
    'false' => [false],
    'an array' => [['admin']],
]);

it('keeps a numeric default guard name as a string, so boot can refuse it by name', function () {
    config(['lukk.guard' => 2]);

    expect(Lukk::defaultGuard())->toBe('2');
});

it('reads the identifier column as email when lukk.username is unset, null, empty or not a string', function (mixed $field) {
    config(['lukk.username' => $field]);

    expect(Lukk::usernameField())->toBe('email');
})->with([
    'null' => [null],
    'an empty env line' => [''],
    'a number' => [5],
    'an array' => [['email']],
]);

it('reads a configured identifier column as it is', function () {
    config(['lukk.username' => 'username']);

    expect(Lukk::usernameField())->toBe('username');
});

it('refuses an identifier column that cannot work as one, naming the fix', function (string $field) {
    // `EloquentUserProvider::retrieveByCredentials()` drops every key containing "password", so such a
    // column looks nothing up and every sign-in fails with an ordinary 422. A dot reads nested
    // request input and becomes a table-qualified column. Neither is a typo the app would notice.
    config(['lukk.username' => $field]);

    expect(fn () => Lukk::usernameField())->toThrow(InvalidArgumentException::class, 'lukk.username');
})->with([
    'a password column' => ['password'],
    'one containing password' => ['backup_Password_hint'],
    'a dotted path' => ['profile.email'],
    'whitespace' => ['user name'],
    'a leading digit' => ['1email'],
]);

it('accepts any plain column name', function (string $field) {
    config(['lukk.username' => $field]);

    expect(Lukk::usernameField())->toBe($field);
})->with(['phone', 'user_name', '_login', 'Email2']);

it('refuses a default guard whose token users come from another provider than its passwords', function () {
    // Sign-in checks the password against `lukk.user_provider`; the lukk-jwt guard resolves the token's
    // `sub` through `auth.guards.<default>.provider`. Pointed at different providers, a `users` password
    // minted a token that resolved to the `admins` row with the same id — an account takeover by
    // configuration, with no error anywhere.
    config([
        'auth.providers.admins' => ['driver' => 'eloquent', 'model' => Lukk\Tests\Fixtures\Admin::class],
        'auth.guards.api' => ['driver' => 'lukk-jwt', 'provider' => 'admins'],
        'lukk.user_provider' => 'users',
    ]);

    expect(fn () => Lukk::assertGuardsIsolated())
        ->toThrow(RuntimeException::class, 'lukk guard [api] resolves its users from the [admins] provider (auth.guards.api.provider), but signs '
            .'them in against [users] (lukk.user_provider) — a password checked in one would mint a token '
            .'for the account with the same id in the other. Point both at the same provider.');
});

it('boots a default guard whose provider matches, or names none, or is not lukk\'s', function (?array $guard) {
    config(['auth.guards.api' => $guard, 'lukk.user_provider' => 'users']);

    expectNoThrow(fn () => Lukk::assertGuardsIsolated());
})->with([
    'the same provider' => [['driver' => 'lukk-jwt', 'provider' => 'users']],
    'no provider' => [['driver' => 'lukk-jwt']],
    'an empty provider' => [['driver' => 'lukk-jwt', 'provider' => '']],
    'another driver' => [['driver' => 'session', 'provider' => 'admins']],
    'no such guard (a verify-elsewhere service)' => [null],
]);

it('boots a default guard whose differently named provider reads the same users', function (array $tokens, array $passwords) {
    // What decides who a token resolves to is the provider's SOURCE — the Eloquent model, the database
    // table — not the name it is registered under: `api_users` and `users` over one model are one table.
    config([
        'auth.providers.api_users' => $tokens,
        'auth.providers.users' => $passwords,
        'auth.guards.api' => ['driver' => 'lukk-jwt', 'provider' => 'api_users'],
        'lukk.user_provider' => 'users',
    ]);

    expectNoThrow(fn () => Lukk::assertGuardsIsolated());
})->with([
    'eloquent, one model' => [
        ['driver' => 'eloquent', 'model' => Lukk\Tests\Fixtures\User::class],
        ['driver' => 'eloquent', 'model' => Lukk\Tests\Fixtures\User::class],
    ],
    'database, one table (no connection named)' => [
        ['driver' => 'database', 'table' => 'users'],
        ['driver' => 'database', 'table' => 'users'],
    ],
    'database, one table on one connection' => [
        ['driver' => 'database', 'table' => 'users', 'connection' => 'pgsql'],
        ['driver' => 'database', 'table' => 'users', 'connection' => 'pgsql'],
    ],
    'a custom driver, identical config' => [
        ['driver' => 'ldap', 'model' => 'App\\Ldap\\User', 'rules' => []],
        ['driver' => 'ldap', 'model' => 'App\\Ldap\\User', 'rules' => []],
    ],
]);

it('refuses a default guard whose differently named provider reads other users', function (array $tokens, array $passwords) {
    config([
        'auth.providers.api_users' => $tokens,
        'auth.providers.users' => $passwords,
        'auth.guards.api' => ['driver' => 'lukk-jwt', 'provider' => 'api_users'],
        'lukk.user_provider' => 'users',
    ]);

    expect(fn () => Lukk::assertGuardsIsolated())
        ->toThrow(RuntimeException::class, 'resolves its users from the [api_users] provider (auth.guards.api.provider), but signs them in against [users]');
})->with([
    'eloquent, another model' => [
        ['driver' => 'eloquent', 'model' => Lukk\Tests\Fixtures\Admin::class],
        ['driver' => 'eloquent', 'model' => Lukk\Tests\Fixtures\User::class],
    ],
    'database, another table' => [
        ['driver' => 'database', 'table' => 'admins'],
        ['driver' => 'database', 'table' => 'users'],
    ],
    'database, one table on another connection' => [
        ['driver' => 'database', 'table' => 'users', 'connection' => 'tenant'],
        ['driver' => 'database', 'table' => 'users'],
    ],
    'another driver over the same name' => [
        ['driver' => 'database', 'table' => 'users'],
        ['driver' => 'eloquent', 'model' => 'users'],
    ],
    'a custom driver, different config' => [
        ['driver' => 'ldap', 'model' => 'App\\Ldap\\User', 'rules' => ['staff']],
        ['driver' => 'ldap', 'model' => 'App\\Ldap\\User', 'rules' => []],
    ],
    'eloquent, model missing on both' => [
        ['driver' => 'eloquent'],
        ['driver' => 'eloquent'],
    ],
    'database, table missing on both' => [
        ['driver' => 'database'],
        ['driver' => 'database'],
    ],
    'driver missing on both' => [
        ['model' => Lukk\Tests\Fixtures\User::class],
        ['model' => Lukk\Tests\Fixtures\User::class],
    ],
]);

it('refuses a differently named provider that is not configured at all', function () {
    // Nothing to compare: the name mismatch stands, as before.
    config([
        'auth.providers.api_users' => null,
        'auth.guards.api' => ['driver' => 'lukk-jwt', 'provider' => 'api_users'],
        'lukk.user_provider' => 'users',
    ]);

    expect(fn () => Lukk::assertGuardsIsolated())->toThrow(RuntimeException::class, '[api_users] provider');

    config(['auth.providers.api_users' => config('auth.providers.users'), 'auth.providers.users' => 'eloquent']);

    expect(fn () => Lukk::assertGuardsIsolated())->toThrow(RuntimeException::class, '[api_users] provider');
});

it('refuses a default guard naming no provider when Laravel\'s default provider is another', function () {
    config(['auth.guards.api' => ['driver' => 'lukk-jwt'], 'auth.defaults.provider' => 'admins', 'lukk.user_provider' => 'users']);

    expect(fn () => Lukk::assertGuardsIsolated())
        ->toThrow(RuntimeException::class, 'resolves its users from the [admins] provider (auth.defaults.provider)');
});
