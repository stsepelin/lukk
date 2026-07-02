<?php

declare(strict_types=1);

namespace Lukk\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Lukk\LukkServiceProvider;
use Lukk\Tests\Fixtures\User;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    use RefreshDatabase;

    protected function getPackageProviders($app): array
    {
        return [LukkServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('a', 32)));
        $app['config']->set('lukk.secret', str_repeat('a', 64));
        // Map the lukk-jwt driver to an 'api' guard, backed by the User fixture.
        $app['config']->set('auth.guards.api', ['driver' => 'lukk-jwt', 'provider' => 'users']);
        $app['config']->set('auth.providers.users.model', User::class);
        // Exercise the 2FA wiring (routes + login branch). Dormant for users
        // without confirmed 2FA, so it doesn't affect the password-only tests.
        $app['config']->set('lukk.features.two_factor', true);
        $app['config']->set('lukk.features.passkeys', true);
        // Register the email-verification routes/wiring. Login gating stays off
        // (block_unverified_login defaults false), so password-only tests are unaffected.
        $app['config']->set('lukk.features.email_verification', true);
        // Password reset: enable the feature + configure the broker it builds on.
        $app['config']->set('lukk.features.password_reset', true);
        $app['config']->set('auth.defaults.passwords', 'users');
        $app['config']->set('auth.passwords.users', [
            'provider' => 'users',
            'table' => 'password_reset_tokens',
            'expire' => 60,
            'throttle' => 60,
        ]);
    }

    protected function defineDatabaseMigrations(): void
    {
        // The package no longer auto-loads migrations (publish-only), so load the
        // core refresh_tokens migration here for the suite.
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('email')->unique();
            $table->string('password');
            $table->text('two_factor_secret')->nullable();
            $table->text('two_factor_recovery_codes')->nullable();
            $table->timestamp('two_factor_confirmed_at')->nullable();
            $table->timestamp('email_verified_at')->nullable();
        });

        Schema::create('password_reset_tokens', function (Blueprint $table) {
            $table->string('email')->primary();
            $table->string('token');
            $table->timestamp('created_at')->nullable();
        });

        Schema::create('passkeys', function (Blueprint $table) {
            $table->string('credential_id')->primary();
            $table->foreignId('user_id')->index();
            $table->string('name')->nullable();
            $table->text('public_key');
            $table->unsignedBigInteger('sign_count')->default(0);
            $table->json('transports')->nullable();
            $table->string('aaguid')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();
        });
    }
}
