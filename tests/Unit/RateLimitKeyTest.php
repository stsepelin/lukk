<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Lukk\Lukk;

afterEach(fn () => Lukk::$rateLimitKeyUsing = null);

function keyFor(string $ip): string
{
    return Lukk::rateLimitKey(Request::create('/', 'POST', server: ['REMOTE_ADDR' => $ip]));
}

it('buckets an IPv6 caller by its /64 by default, even with no prefix configured at all', function () {
    expect(keyFor('2001:db8:1:2:3:4:5:6'))->toBe('2001:db8:1:2::/64');

    config(['lukk.rate_limits.ipv6_prefix' => null]);
    expect(keyFor('2001:db8:1:2:3:4:5:6'))->toBe('2001:db8:1:2::/64');
});

it('keys a request with no address as unknown, not every caller as one', function () {
    $request = Request::create('/', 'POST');
    $request->server->remove('REMOTE_ADDR');

    expect(Lukk::rateLimitKey($request))->toBe('unknown');
});

it('takes the prefix from env as a string, and masks inside a byte when it does not fall on one', function () {
    // `env()` hands "60" over as a string — under strict_types `intdiv()` would throw on it uncast.
    config(['lukk.rate_limits.ipv6_prefix' => '60']);
    expect(keyFor('2001:db8:1:2ff:3:4:5:6'))->toBe('2001:db8:1:2f0::/60');

    // One bit into the byte: the partial byte is still kept, masked to its top bit.
    config(['lukk.rate_limits.ipv6_prefix' => 57]);
    expect(keyFor('2001:db8:1:ff:3:4:5:6'))->toBe('2001:db8:1:80::/57');
});

it('clamps the prefix to /32../128', function () {
    config(['lukk.rate_limits.ipv6_prefix' => 20]);
    expect(keyFor('2001:db8:1:2:3:4:5:6'))->toBe('2001:db8::/32');

    config(['lukk.rate_limits.ipv6_prefix' => 32]);
    expect(keyFor('2001:db8:1:2:3:4:5:6'))->toBe('2001:db8::/32');

    config(['lukk.rate_limits.ipv6_prefix' => 200]);
    expect(keyFor('2001:db8:1:2:3:4:5:6'))->toBe('2001:db8:1:2:3:4:5:6/128');

    config(['lukk.rate_limits.ipv6_prefix' => 128]);
    expect(keyFor('2001:db8:1:2:3:4:5:6'))->toBe('2001:db8:1:2:3:4:5:6/128');
});

it('unwraps an IPv4-mapped or well-known-NAT64 address to the IPv4 it carries', function () {
    expect(keyFor('::ffff:1.2.3.4'))->toBe('1.2.3.4')
        ->and(keyFor('64:ff9b::1.2.3.4'))->toBe('1.2.3.4');
});

it('unwraps only the exact embedding prefixes, not addresses that merely start like them', function () {
    // `::1` shares the mapped prefix's first ten zero bytes; RFC 8215's local-use NAT64 range
    // (64:ff9b:1::/48) and 64:ff9b::1:0:… share the well-known prefix's first bytes. None carries an IPv4.
    expect(keyFor('::1'))->toBe('::/64')
        ->and(keyFor('64:ff9b:1::1.2.3.4'))->toBe('64:ff9b:1::/64')
        ->and(keyFor('64:ff9b::1:0:102:304'))->toBe('64:ff9b::/64')
        // Every byte of the well-known prefix but the last is zero here — the last one decides.
        ->and(keyFor('64:ff9b::1:0:0'))->toBe('64:ff9b::/64');
});

it('keys on a custom callback\'s value as a string, even when it returns a number', function () {
    // The callback is the app's: a numeric id is a perfectly good key, and the return type is string.
    Lukk::rateLimitKeyUsing(fn () => 42);
    expect(keyFor('203.0.113.9'))->toBe('42');
});
