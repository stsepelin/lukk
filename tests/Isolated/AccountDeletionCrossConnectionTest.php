<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Lukk\Actions\DeleteAccount;
use Lukk\Lukk;
use Lukk\Models\RefreshToken;
use Lukk\Tests\Fixtures\OtherConnectionUser;
use Lukk\Tests\TestCase;

uses(TestCase::class)->group('account-deletion');

/** A users table in a second database, with the provider pointed at it. */
function directoryUser(string $email = 'directory@example.test'): OtherConnectionUser
{
    config(['database.connections.directory' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']]);

    if (! Schema::connection('directory')->hasTable('users')) {
        Schema::connection('directory')->create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->unique();
            $table->string('password');
            $table->timestamps();
        });
    }

    config(['auth.providers.users.model' => OtherConnectionUser::class]);

    return OtherConnectionUser::create(['email' => $email, 'password' => bcrypt('password')]);
}

it('rolls the user row back too when the provider is on another connection', function () {
    // The erasure transaction belongs to lukk's connection. A provider model on a different one —
    // identities in a shared directory database, application tables local — ran the disposal with
    // NO transaction, so it committed the instant it executed: a rollback afterwards restored the
    // refresh tokens around a user that was already permanently gone. Deleted forever, and still
    // logged in everywhere as far as the surviving rows were concerned.
    $user = directoryUser();
    $user->startSession();

    // A multi-step anonymize that fails halfway — the documented use for this callback, and so its
    // most likely failure rather than its least.
    Lukk::deleteUserUsing(function ($subject) {
        $subject->forceDelete();

        throw new RuntimeException('anonymize failed halfway');
    });

    expect(fn () => app(DeleteAccount::class)($user))->toThrow(RuntimeException::class);

    expect(OtherConnectionUser::find($user->getKey()))->not->toBeNull()
        ->and(RefreshToken::where('user_id', $user->getKey())->count())->toBe(1);
});

it('still erases across connections when nothing throws', function () {
    // The nesting must not cost the ordinary path: a cross-connection erasure that succeeds has to
    // commit on BOTH connections.
    $user = directoryUser('second@example.test');
    $user->startSession();

    app(DeleteAccount::class)($user);

    expect(OtherConnectionUser::find($user->getKey()))->toBeNull()
        ->and(RefreshToken::where('user_id', $user->getKey())->count())->toBe(0);
});

it('erases a non-Eloquent user, which has no connection to nest on', function () {
    // `lukk.user_provider` can point at a provider whose model isn't Eloquent, and such a user
    // exposes no connection — so there is nothing to open a transaction on and the disposal runs
    // directly. Erasure must still work rather than fatal on `getConnection()`.
    $user = new class implements Authenticatable
    {
        public bool $erased = false;

        public function getAuthIdentifierName(): string
        {
            return 'id';
        }

        public function getAuthIdentifier(): int
        {
            return 4242;
        }

        public function getAuthPasswordName(): string
        {
            return 'password';
        }

        public function getAuthPassword(): string
        {
            return '';
        }

        public function getRememberToken(): string
        {
            return '';
        }

        public function setRememberToken($value): void {}

        public function getRememberTokenName(): string
        {
            return '';
        }
    };

    Lukk::deleteUserUsing(function ($subject) {
        $subject->erased = true;
    });

    app(DeleteAccount::class)($user);

    expect($user->erased)->toBeTrue();
});
