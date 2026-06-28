<?php

declare(strict_types=1);

use Lukk\Support\OptionalDependency;

it('throws an actionable error when an optional feature library is missing', function () {
    expect(fn () => OptionalDependency::ensure('Lukk\Missing\Library', 'vendor/passkeys', 'passkeys'))
        ->toThrow(RuntimeException::class, 'composer require vendor/passkeys');
});

it('passes silently when the library is installed', function () {
    OptionalDependency::ensure(stdClass::class, 'vendor/passkeys', 'passkeys');

    expect(true)->toBeTrue();
});
