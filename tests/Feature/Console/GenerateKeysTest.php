<?php

declare(strict_types=1);

it('generates an RS256 keypair and prints the env to set', function () {
    $this->artisan('lukk:keygen')
        ->expectsOutputToContain('-----BEGIN')
        ->expectsOutputToContain('LUKK_ALGORITHM=RS256')
        ->assertSuccessful();
});

it('generates an ES256 keypair with a chosen kid', function () {
    $this->artisan('lukk:keygen', ['--algorithm' => 'ES256', '--kid' => 'my-kid'])
        ->expectsOutputToContain('LUKK_ALGORITHM=ES256')
        ->expectsOutputToContain('LUKK_ACTIVE_KID=my-kid')
        ->assertSuccessful();
});

it('rejects an unsupported algorithm', function () {
    $this->artisan('lukk:keygen', ['--algorithm' => 'HS256'])
        ->expectsOutputToContain('Unsupported algorithm')
        ->assertFailed();
});
