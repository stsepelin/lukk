<?php

declare(strict_types=1);

namespace Lukk\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Lukk\Tests\Fixtures\Admin;

/**
 * Boots two isolated lukk-jwt guards — the default `api` (users) and `admin` (admins) — each with
 * its own crypto identity, plus the `guard`-column schema. The base for the cross-guard isolation
 * tests: a token/family for one guard must be invisible to the other even when ids collide.
 */
class MultiGuardTestCase extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        // The default (users) guard gets an explicit, distinct identity.
        $app['config']->set('lukk.issuer', 'https://users.test');
        $app['config']->set('lukk.audience', ['https://users.test']);

        // A second guard + its provider, declared the Laravel-native way.
        $app['config']->set('auth.guards.admin', ['driver' => 'lukk-jwt', 'provider' => 'admins']);
        $app['config']->set('auth.providers.admins', ['driver' => 'eloquent', 'model' => Admin::class]);

        // The admin guard's lukk crypto identity: distinct secret AND audience, mounted at admin/auth.
        $app['config']->set('lukk.guards.admin', [
            'issuer' => 'https://admin.test',
            'audience' => ['https://admin.test'],
            'secret' => str_repeat('b', 64),
            'path' => 'admin/auth',
        ]);
    }

    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();

        // A separate admins table, so admins.id collides with users.id.
        Schema::create('admins', function (Blueprint $table) {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->unique();
            $table->string('password');
            $table->text('two_factor_secret')->nullable();
            $table->text('two_factor_recovery_codes')->nullable();
            $table->timestamp('two_factor_confirmed_at')->nullable();
            $table->timestamp('email_verified_at')->nullable();
        });
    }
}
