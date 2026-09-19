<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;

/**
 * Run `lukk:keygen` and split what it printed into the parts an operator copies out.
 *
 * @param  array<string, string>  $options
 * @return array{lines: list<string>, private: OpenSSLAsymmetricKey, public: OpenSSLAsymmetricKey, kid: string}
 */
function keygen(array $options = []): array
{
    expect(Artisan::call('lukk:keygen', $options))->toBe(0);

    $output = Artisan::output();

    preg_match('/-----BEGIN PRIVATE KEY-----.+?-----END PRIVATE KEY-----/s', $output, $private);
    preg_match('/-----BEGIN PUBLIC KEY-----.+?-----END PUBLIC KEY-----/s', $output, $public);
    preg_match('/^LUKK_ACTIVE_KID=(.*)$/m', $output, $kid);

    return [
        'lines' => explode("\n", $output),
        'private' => openssl_pkey_get_private($private[0]),
        'public' => openssl_pkey_get_public($public[0]),
        'kid' => $kid[1],
    ];
}

/** Whether the two halves are one keypair: sign with the private key, verify with the public one. */
function isOnePair(OpenSSLAsymmetricKey $private, OpenSSLAsymmetricKey $public): bool
{
    openssl_sign('payload', $signature, $private, OPENSSL_ALGO_SHA256);

    return openssl_verify('payload', $signature, $public, OPENSSL_ALGO_SHA256) === 1;
}

it('generates an RSA-2048 keypair for RS256 by default', function () {
    $keys = keygen();
    $details = openssl_pkey_get_details($keys['public']);

    expect($details['type'])->toBe(OPENSSL_KEYTYPE_RSA)
        ->and($details['bits'])->toBe(2048)
        ->and(isOnePair($keys['private'], $keys['public']))->toBeTrue()
        ->and($keys['lines'])->toContain('LUKK_ALGORITHM=RS256');
});

it('generates an EC P-256 keypair for ES256, whatever the case of the option', function () {
    $keys = keygen(['--algorithm' => 'es256']);
    $details = openssl_pkey_get_details($keys['public']);

    expect($details['type'])->toBe(OPENSSL_KEYTYPE_EC)
        ->and($details['ec']['curve_name'])->toBe('prime256v1')
        ->and(isOnePair($keys['private'], $keys['public']))->toBeTrue()
        ->and($keys['lines'])->toContain('LUKK_ALGORITHM=ES256');
});

it('labels the key with a random id unless one is chosen', function () {
    $first = keygen()['kid'];

    expect($first)->toMatch('/^k[0-9a-f]{8}$/')
        ->and(keygen()['kid'])->not->toBe($first)
        ->and(keygen(['--kid' => 'my-kid'])['kid'])->toBe('my-kid');
});

it('prints the keys, then exactly the env to set', function () {
    // Compared whole, with only the key material masked: the blank lines framing each PEM are what
    // let an operator copy one out cleanly, and every line after them is copied verbatim into .env.
    Artisan::call('lukk:keygen', ['--kid' => 'my-kid']);
    $output = preg_replace('/-----BEGIN (\w+) KEY-----.+?-----END \1 KEY-----/s', '<$1>', Artisan::output());

    expect($output)->toBe(implode("\n", [
        '',
        '   INFO  Generated an RS256 keypair (kid: my-kid).  ',
        '',
        '',
        '<PRIVATE>',
        '',
        '<PUBLIC>',
        '',
        '',
        'Store the keys, then set in your .env:',
        'LUKK_ALGORITHM=RS256',
        'LUKK_ACTIVE_KID=my-kid',
        'LUKK_PRIVATE_KEY=@/path/to/private.pem   # or paste the PEM inline',
        'LUKK_PUBLIC_KEY=@/path/to/public.pem',
        '',
    ]));
});

it('rejects an unsupported algorithm', function () {
    command('lukk:keygen', ['--algorithm' => 'hs256'])
        ->expectsOutputToContain('Unsupported algorithm [HS256]. Use RS256 or ES256.')
        ->assertFailed();
});
