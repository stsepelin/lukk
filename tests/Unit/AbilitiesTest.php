<?php

declare(strict_types=1);

use Lukk\Lukk;
use Lukk\Support\Abilities;
use Lukk\Support\TokenContext;

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

it('matches abilities case-sensitively', function () {
    // `scope` values are opaque strings (RFC 6749 §3.3), and case-insensitive matching would make
    // `Orders.Read` satisfy a gate on `orders.read` — an ability nobody granted under that name.
    $granted = Abilities::fromScope('orders.read Billing.*');

    expect($granted->can('ORDERS.READ'))->toBeFalse()
        ->and($granted->can('Orders.Read'))->toBeFalse()
        ->and($granted->can('orders.read'))->toBeTrue()
        ->and($granted->can('billing.view'))->toBeFalse()
        ->and($granted->can('Billing.view'))->toBeTrue();
});

it('rejects every character a scope token may not contain', function () {
    // RFC 6749 §3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ). The space is the dangerous one —
    // the claim is space-delimited, so `orders.read admin` parses back as TWO abilities — but a
    // quote, a backslash, a control character or a non-ASCII byte have no defined meaning either.
    foreach (['orders.read admin', 'a"b', 'a\\b', "a\nb", "a\tb", 'café', ' ', 'a b'] as $bad) {
        expect(fn () => Abilities::fromArray([$bad]))
            ->toThrow(InvalidArgumentException::class, 'not a valid scope token');
    }

    // ...and accepts the full legal range, punctuation included.
    expect(Abilities::fromArray(['!', '#', '[', ']', '~', 'orders:read', "a'b", '0'])->all())
        ->toBe(['!', '#', '[', ']', '~', 'orders:read', "a'b", '0']);
});

it('drops empty strings and duplicates without complaining', function () {
    // An empty entry is a formatting artefact (a trailing comma in a config array), not a mistake
    // worth failing a login over — unlike a malformed one, it cannot widen the grant.
    expect(Abilities::fromArray(['orders.read', '', 'orders.read', 'orders.write'])->toScope())
        ->toBe('orders.read orders.write');
});

it('refuses a non-string ability, but accepts a Stringable one', function () {
    // A backed enum or a permission model is the likely shape; `(string)` on an array or an object
    // without __toString used to 500 every login AND every refresh.
    expect(fn () => Abilities::fromArray([['orders.read']]))
        ->toThrow(InvalidArgumentException::class, 'must be strings')
        ->and(fn () => Abilities::fromArray([null]))
        ->toThrow(InvalidArgumentException::class, 'must be strings');

    $stringable = new class
    {
        public function __toString(): string
        {
            return 'orders.read';
        }
    };

    expect(Abilities::fromArray([$stringable])->all())->toBe(['orders.read']);
});

it('reports "not configured" as null, distinct from "configured and granted nothing"', function () {
    // The two mean different things to the issuer: null leaves `scope` alone (an install that never
    // opted in keeps byte-identical tokens), while an empty grant ERASES it.
    $context = new TokenContext('api', 1, 'fid');

    expect(Lukk::abilitiesFor(1, $context))->toBeNull();

    Lukk::abilitiesUsing(fn () => []);
    expect(Lukk::abilitiesFor(1, $context))->toBeInstanceOf(Abilities::class)
        ->and(Lukk::abilitiesFor(1, $context)->toScope())->toBeNull();

    Lukk::$abilitiesUsing = null;
});
