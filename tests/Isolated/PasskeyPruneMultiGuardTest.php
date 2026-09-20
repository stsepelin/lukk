<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Lukk;
use Lukk\Models\Passkey;
use Lukk\Support\NewPasskey;
use Lukk\Tests\Fixtures\Admin;
use Lukk\Tests\Fixtures\OtherConnectionUser;
use Lukk\Tests\Fixtures\User;
use Lukk\Tests\MultiGuardTestCase;

uses(MultiGuardTestCase::class)->group('passkeys', 'multi-guard');

/** One live credential and one orphan on the given guard. */
function seedGuard(string $guard, int|string $liveId): void
{
    Lukk::useGuard($guard);
    app(PasskeyRepository::class)->store($liveId, new NewPasskey("{$guard}-live", 'cose', 0));
    app(PasskeyRepository::class)->store(999999, new NewPasskey("{$guard}-ghost", 'cose', 0));
    Lukk::useGuard(null);
}

it('sweeps the default guard too, not only the extra ones', function () {
    seedGuard('api', User::factory()->create()->getKey());

    expect(app(PasskeyRepository::class)->pruneOrphaned())->toBe(1)
        ->and(Passkey::find('api-live'))->not->toBeNull()
        ->and(Passkey::find('api-ghost'))->toBeNull();
});

it('names the default guard "api" when lukk.guard is null', function () {
    seedGuard('api', User::factory()->create()->getKey());
    config(['lukk.guard' => null]);

    expect(app(PasskeyRepository::class)->pruneOrphaned())->toBe(1)
        ->and(Passkey::find('api-ghost'))->toBeNull();
});

it('resolves the default guard from lukk.user_provider, not its own auth.guards entry', function () {
    // As `userProviderFor()` does. Read from `auth.guards.api.provider` instead, the users would be
    // judged against the admins table and a live user's passkey deleted.
    seedGuard('api', User::factory()->create(['id' => 4242])->getKey());
    config(['auth.guards.api.provider' => 'admins']);

    app(PasskeyRepository::class)->pruneOrphaned();

    expect(Passkey::find('api-live'))->not->toBeNull();
});

it('still sweeps the next guard after skipping a non-Eloquent provider', function () {
    // The default guard is listed first, so a `break` there would leave every later guard unswept.
    seedGuard('admin', Admin::factory()->create()->getKey());
    config(['auth.providers.users' => ['driver' => 'session']]);

    expect(app(PasskeyRepository::class)->pruneOrphaned())->toBe(1)
        ->and(Passkey::find('admin-ghost'))->toBeNull();
});

it('still sweeps the next guard after skipping a provider on another connection', function () {
    config([
        'database.connections.directory' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => ''],
        'auth.providers.users.model' => OtherConnectionUser::class,
    ]);
    Schema::connection('directory')->create('users', function (Blueprint $table) {
        $table->id();
    });
    seedGuard('admin', Admin::factory()->create()->getKey());

    expect(app(PasskeyRepository::class)->pruneOrphaned())->toBe(1)
        ->and(Passkey::find('admin-ghost'))->toBeNull();
});
