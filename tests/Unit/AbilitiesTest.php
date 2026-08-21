<?php

declare(strict_types=1);

use Lukk\Support\Abilities;

uses()->group('abilities');

it('grants nothing when there is no scope claim', function () {
    // Deny by default. The alternative — absent means unrestricted — turns a forgotten
    // `abilitiesUsing` into a route gate that silently passes everyone.
    foreach ([null, '', '   ', 123, [], (object) []] as $scope) {
        expect(Abilities::fromScope($scope)->can('orders.read'))->toBeFalse();
    }
});

it('parses the space-delimited claim', function () {
    $a = Abilities::fromScope('orders.read  orders.write   users.read');

    expect($a->all())->toBe(['orders.read', 'orders.write', 'users.read'])
        ->and($a->can('orders.write'))->toBeTrue()
        ->and($a->can('users.write'))->toBeFalse();
});

it('treats * as everything', function () {
    expect(Abilities::fromScope('*')->can('anything.at.all'))->toBeTrue();
});

it('expands a prefix wildcard but not the bare namespace', function () {
    $a = Abilities::fromScope('orders.*');

    expect($a->can('orders.read'))->toBeTrue()
        ->and($a->can('orders.line.delete'))->toBeTrue()
        // `orders.*` is about what lives UNDER the namespace. Including the namespace itself would
        // make `orders.*` and `orders` indistinguishable to anyone reading a policy.
        ->and($a->can('orders'))->toBeFalse()
        // And it must not leak sideways into a name that merely starts with the same letters.
        ->and($a->can('ordersX.read'))->toBeFalse();
});

it('never lets the CHECK carry a wildcard', function () {
    // A caller asking `tokenCan('orders.*')` is asking whether that literal ability was granted —
    // otherwise anyone holding one narrow ability could widen their own question to the namespace.
    expect(Abilities::fromScope('orders.read')->can('orders.*'))->toBeFalse()
        ->and(Abilities::fromScope('orders.read')->can('*'))->toBeFalse()
        // Granted literally, it matches literally.
        ->and(Abilities::fromScope('orders.*')->can('orders.*'))->toBeTrue();
});

it('refuses an empty ability', function () {
    expect(Abilities::fromScope('*')->can(''))->toBeFalse();
});

it('distinguishes any-of from all-of, and refuses an empty requirement', function () {
    $a = Abilities::fromScope('orders.read');

    expect($a->canAny(['orders.read', 'users.read']))->toBeTrue()
        ->and($a->canAll(['orders.read', 'users.read']))->toBeFalse()
        ->and($a->canAll(['orders.read']))->toBeTrue()
        // Requiring nothing must not read as "satisfied" — a middleware given no arguments should
        // refuse rather than wave the request through.
        ->and($a->canAll([]))->toBeFalse()
        ->and($a->canAny([]))->toBeFalse();
});

it('round-trips to a claim, and mints no claim for an empty grant', function () {
    expect(Abilities::fromArray(['a', 'b'])->toScope())->toBe('a b')
        ->and(Abilities::fromArray([])->toScope())->toBeNull()
        ->and(Abilities::fromArray(['a', '', 'b'])->toScope())->toBe('a b');
});
