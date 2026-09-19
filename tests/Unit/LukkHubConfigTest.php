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
