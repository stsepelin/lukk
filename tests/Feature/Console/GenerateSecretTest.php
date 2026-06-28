<?php

declare(strict_types=1);

beforeEach(function () {
    $this->envPath = sys_get_temp_dir().'/lukk-secret-test-'.getmypid().'.env';
    $this->app->useEnvironmentPath(dirname($this->envPath));
    $this->app->loadEnvironmentFrom(basename($this->envPath));
});

afterEach(function () {
    @unlink($this->envPath);
});

it('writes a fresh 256-bit secret into the .env file', function () {
    config(['lukk.secret' => null]); // simulate an unconfigured install
    file_put_contents($this->envPath, "APP_NAME=Lukk\n");

    $this->artisan('lukk:secret')
        ->expectsOutputToContain('Lukk signing secret set successfully.')
        ->assertSuccessful();

    $contents = file_get_contents($this->envPath);
    expect($contents)->toMatch('/^LUKK_SECRET=[0-9a-f]{64}$/m');
    // The running config reflects the new key immediately.
    expect(strlen((string) config('lukk.secret')))->toBe(64);
});

it('replaces an existing secret in place with --force', function () {
    file_put_contents($this->envPath, "LUKK_SECRET=old\nLUKK_ISSUER=https://api.example.com\n");

    $this->artisan('lukk:secret', ['--force' => true])->assertSuccessful();

    $contents = file_get_contents($this->envPath);
    expect($contents)
        ->not->toContain('LUKK_SECRET=old')
        ->toContain('LUKK_ISSUER=https://api.example.com')
        ->toMatch('/^LUKK_SECRET=[0-9a-f]{64}$/m');
    // No duplicate key appended.
    expect(substr_count($contents, 'LUKK_SECRET='))->toBe(1);
});

it('prints the secret without writing when given --show', function () {
    file_put_contents($this->envPath, "LUKK_SECRET=keepme\n");

    $this->artisan('lukk:secret', ['--show' => true])->assertSuccessful();

    expect(file_get_contents($this->envPath))->toContain('LUKK_SECRET=keepme');
});

it('aborts when no .env file exists', function () {
    $this->artisan('lukk:secret', ['--force' => true])
        ->expectsOutputToContain('No .env file found.')
        ->assertFailed();
});

it('aborts without writing when the user declines to overwrite', function () {
    config(['lukk.secret' => str_repeat('a', 64)]);
    file_put_contents($this->envPath, 'LUKK_SECRET='.str_repeat('a', 64)."\n");

    $this->artisan('lukk:secret')
        ->expectsConfirmation('A Lukk secret already exists. Overwrite it?', 'no')
        ->assertFailed();

    expect(file_get_contents($this->envPath))->toContain('LUKK_SECRET='.str_repeat('a', 64));
});
