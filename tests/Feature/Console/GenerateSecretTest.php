<?php

declare(strict_types=1);

/**
 * Where the fixture `.env` lives for this test file.
 *
 * Derived, not stored. It used to be `$this->envPath`, assigned to the TestCase from inside a Pest
 * closure — a dynamic property declared nowhere, which the analyser cannot see and a future PHP
 * deprecates. Same process, same path, so every hook agrees without holding state.
 */
function secretEnvPath(): string
{
    return sys_get_temp_dir().'/lukk-secret-test-'.getmypid().'.env';
}
beforeEach(function () {
    app()->useEnvironmentPath(dirname(secretEnvPath()));
    app()->loadEnvironmentFrom(basename(secretEnvPath()));
});

afterEach(function () {
    @unlink(secretEnvPath());
});

it('writes a fresh 256-bit secret into the .env file', function () {
    config(['lukk.secret' => null]); // simulate an unconfigured install
    file_put_contents(secretEnvPath(), "APP_NAME=Lukk\n");

    command('lukk:secret')
        ->expectsOutputToContain('Lukk signing secret set successfully.')
        ->assertSuccessful();

    $contents = file_get_contents(secretEnvPath());
    expect($contents)->toMatch('/^LUKK_SECRET=[0-9a-f]{64}$/m');
    // The running config reflects the new key immediately.
    expect(strlen((string) config('lukk.secret')))->toBe(64);
});

it('replaces an existing secret in place with --force', function () {
    file_put_contents(secretEnvPath(), "LUKK_SECRET=old\nLUKK_ISSUER=https://api.example.com\n");

    command('lukk:secret', ['--force' => true])->assertSuccessful();

    $contents = file_get_contents(secretEnvPath());
    expect($contents)
        ->not->toContain('LUKK_SECRET=old')
        ->toContain('LUKK_ISSUER=https://api.example.com')
        ->toMatch('/^LUKK_SECRET=[0-9a-f]{64}$/m');
    // No duplicate key appended.
    expect(substr_count($contents, 'LUKK_SECRET='))->toBe(1);
});

it('writes a per-guard secret to LUKK_<GUARD>_SECRET with --guard', function () {
    file_put_contents(secretEnvPath(), "APP_NAME=Lukk\n");

    command('lukk:secret', ['--guard' => 'admin'])->assertSuccessful();

    $contents = file_get_contents(secretEnvPath());
    expect($contents)->toMatch('/^LUKK_ADMIN_SECRET=[0-9a-f]{64}$/m')
        ->not->toContain('LUKK_SECRET=');
    // The running config reflects the new per-guard key.
    expect(strlen((string) config('lukk.guards.admin.secret')))->toBe(64);
});

it('prints the secret without writing when given --show', function () {
    file_put_contents(secretEnvPath(), "LUKK_SECRET=keepme\n");

    command('lukk:secret', ['--show' => true])->assertSuccessful();

    expect(file_get_contents(secretEnvPath()))->toContain('LUKK_SECRET=keepme');
});

it('aborts when no .env file exists', function () {
    command('lukk:secret', ['--force' => true])
        ->expectsOutputToContain('No .env file found.')
        ->assertFailed();
});

it('aborts without writing when the user declines to overwrite', function () {
    config(['lukk.secret' => str_repeat('a', 64)]);
    file_put_contents(secretEnvPath(), 'LUKK_SECRET='.str_repeat('a', 64)."\n");

    command('lukk:secret')
        ->expectsConfirmation('A Lukk secret already exists. Overwrite it?', 'no')
        ->assertFailed();

    expect(file_get_contents(secretEnvPath()))->toContain('LUKK_SECRET='.str_repeat('a', 64));
});
