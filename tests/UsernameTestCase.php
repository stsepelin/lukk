<?php

declare(strict_types=1);

namespace Lukk\Tests;

use Illuminate\Database\Schema\Blueprint;

/**
 * Boots the suite with the identifier overridden to `username` (`lukk.username`) and a matching
 * users table (a required unique `username`, an optional `email`), so a test can prove login +
 * registration authenticate by a non-email column.
 */
class UsernameTestCase extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('lukk.username', 'username');
    }

    protected function defineUsersTable(Blueprint $table): void
    {
        $table->id();
        $table->string('name')->nullable();
        $table->string('username')->unique();
        $table->string('email')->nullable()->unique();
        $table->string('password');
        $table->text('two_factor_secret')->nullable();
        $table->text('two_factor_recovery_codes')->nullable();
        $table->timestamp('two_factor_confirmed_at')->nullable();
        $table->timestamp('email_verified_at')->nullable();
    }
}
