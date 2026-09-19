<?php

declare(strict_types=1);

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\FileStore;
use Illuminate\Cache\NullStore;
use Illuminate\Cache\Repository;
use Illuminate\Filesystem\Filesystem;
use Lukk\Support\CacheStoreGuard;

afterEach(fn () => app()->detectEnvironment(fn () => 'testing'));

function inProduction(): void
{
    app()->detectEnvironment(fn () => 'production');
}

it('refuses, in production, a store that keeps nothing another process can see', function (string $class, object $store) {
    inProduction();

    expect(fn () => CacheStoreGuard::assertCanHoldRevocations(new Repository($store)))->toThrow(
        RuntimeException::class,
        "lukk cannot use the [{$class}] cache store: token revocation, two-factor replay protection and passkey challenges all live there, and it keeps nothing another process can see. Point LUKK_DENYLIST_STORE at a shared, persistent store (Redis) — and never one your deploy flushes, since `cache:clear` would resurrect every token revoked in the last access_ttl.",
    );
})->with([
    'array' => ['ArrayStore', new ArrayStore],
    'null' => ['NullStore', new NullStore],
]);

it('accepts a shared store in production', function () {
    inProduction();

    expectNoThrow(fn () => CacheStoreGuard::assertCanHoldRevocations(new Repository(new FileStore(new Filesystem, sys_get_temp_dir()))));
});

it('accepts any store outside production — the array store is the right one for a test suite', function () {
    expectNoThrow(fn () => CacheStoreGuard::assertCanHoldRevocations(new Repository(new ArrayStore)));
});
