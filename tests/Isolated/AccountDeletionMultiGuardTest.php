<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Lukk\Actions\DeleteAccount;
use Lukk\Actions\ExportAccount;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Lukk;
use Lukk\Models\Passkey;
use Lukk\Models\RefreshToken;
use Lukk\Passkeys\PasskeyChallengeStore;
use Lukk\Support\NewPasskey;
use Lukk\Tests\Fixtures\Admin;
use Lukk\Tests\Fixtures\OtherConnectionAdmin;
use Lukk\Tests\Fixtures\User;
use Lukk\Tests\MultiGuardTestCase;

uses(MultiGuardTestCase::class)->group('account-deletion', 'multi-guard');

it('erases only this guard\'s account, not a colliding id on another', function () {
    // An account is (guard, id) — not id. Providers are separate tables, so `users.id === admins.id`
    // is the ordinary case, and erasure once destroyed an unrelated admin's refresh tokens: a
    // permanent logout of a live account, with no `revoked_at` to explain it and no denylist entry,
    // because revocation IS guard-scoped and the delete was not.
    $user = User::factory()->create();
    $admin = Admin::factory()->create();
    expect($admin->getKey())->toBe($user->getKey());

    $user->startSession();
    app('auth')->forgetGuards();
    $adminPair = $admin->startSession();
    app('auth')->forgetGuards();

    app(DeleteAccount::class)($user);

    expect(User::find($user->getKey()))->toBeNull()
        ->and(Admin::find($admin->getKey()))->not->toBeNull()
        ->and(RefreshToken::where('guard', 'admin')->count())->toBe(1);

    // ...and the admin's session still works.
    $this->withToken($adminPair->accessToken)->postJson('/admin/auth/logout')->assertSuccessful();
});

it('never exports another subject\'s sessions', function () {
    // Art. 15(4): the right of access must not adversely affect others. Reading the model directly
    // rather than the guard-scoped repository handed the customer the admin's family ids, session
    // count and login timestamps — behavioural data about a third party.
    $user = User::factory()->create();
    $admin = Admin::factory()->create();

    $user->startSession();
    app('auth')->forgetGuards();
    $admin->startSession();
    app('auth')->forgetGuards();
    $admin->startSession();

    $export = app(ExportAccount::class)($user);

    expect($export['sessions'])->toHaveCount(1);
});

it('never prunes a passkey belonging to another guard\'s provider', function () {
    // `passkeys` has no `guard` column, so orphanhood was decided against ONE users table — which
    // makes every credential of every other provider orphaned by construction. `lukk:prune` is
    // `->daily()` by default, so this silently deleted a live admin's second factor, every day,
    // irreversibly. It is the same guard-isolation bug already fixed on the refresh-token
    // repository, in the sibling repository that was missed.
    $admin = Admin::factory()->create();
    Lukk::useGuard('admin');
    app(PasskeyRepository::class)->store($admin->getKey(), new NewPasskey('admin-cred', 'cose', 0), 'Admin Yubikey');

    // A genuinely orphaned row on the SAME guard — no admin claims id 999999 — must still go, or
    // the fix would be "stop pruning" rather than "prune correctly".
    app(PasskeyRepository::class)->store(999999, new NewPasskey('ghost-cred', 'cose', 0), 'Ghost');
    Lukk::useGuard(null);

    $this->artisan('lukk:prune')->assertSuccessful();

    expect(Passkey::find('admin-cred'))->not->toBeNull()
        ->and(Passkey::find('ghost-cred'))->toBeNull();
});

it('skips a guard whose provider is non-Eloquent rather than deleting its rows', function () {
    // A provider lukk cannot introspect has no table to compare against, so its guard's rows cannot
    // be judged. Skipping is the safe direction — the alternative reads every row as orphaned.
    $admin = Admin::factory()->create();
    Lukk::useGuard('admin');
    app(PasskeyRepository::class)->store($admin->getKey(), new NewPasskey('admin-cred', 'cose', 0), 'Admin Yubikey');
    app(PasskeyRepository::class)->store(999999, new NewPasskey('ghost-cred', 'cose', 0), 'Ghost');
    Lukk::useGuard(null);

    config(['auth.providers.admins' => ['driver' => 'session']]);
    $this->artisan('lukk:prune')->assertSuccessful();

    expect(Passkey::count())->toBe(2);
});

it('never erases or discloses a colliding admin\'s passkeys', function () {
    // `passkeys` had no `guard` column, so `deleteForUser`/`summariesForUser` were bare
    // `where('user_id', ...)` — and under multi-guard `users.id === admins.id` is the ORDINARY case,
    // because the providers are separate tables. Erasing the customer therefore destroyed a live,
    // privileged account's second factor, and exporting the customer handed them that admin's device
    // name and last-used timestamp: behavioural data about a third party, which the sibling session
    // test above already calls out as forbidden by Art. 15(4).
    $user = User::factory()->create();
    $admin = Admin::factory()->create();
    expect($admin->getKey())->toBe($user->getKey());

    Lukk::useGuard('admin');
    app(PasskeyRepository::class)->store($admin->getKey(), new NewPasskey('admin-cred', 'cose', 0), 'Admin Yubikey');
    Lukk::useGuard(null);
    app(PasskeyRepository::class)->store($user->getKey(), new NewPasskey('user-cred', 'cose', 0), 'Phone');

    $export = app(ExportAccount::class)($user);
    expect($export['passkeys'])->toHaveCount(1)
        ->and($export['passkeys'][0]['credential_id'])->toBe('user-cred');

    app(DeleteAccount::class)($user);

    expect(Passkey::find('user-cred'))->toBeNull()
        ->and(Passkey::find('admin-cred'))->not->toBeNull();
});

it('never lets one guard assert another guard\'s credential', function () {
    // The assertion lookup takes a credential id and NO user — it is what decides who just
    // authenticated. Unscoped, an admin's credential resolved on the users guard, which is a
    // straight authentication bypass across the isolation boundary rather than a data-tidiness bug.
    $admin = Admin::factory()->create();

    Lukk::useGuard('admin');
    app(PasskeyRepository::class)->store($admin->getKey(), new NewPasskey('admin-cred', 'cose', 0), 'Admin Yubikey');
    expect(app(PasskeyRepository::class)->findByCredentialId('admin-cred'))->not->toBeNull();

    Lukk::useGuard(null);
    expect(app(PasskeyRepository::class)->findByCredentialId('admin-cred'))->toBeNull()
        ->and(app(PasskeyRepository::class)->credentialIdsFor($admin->getKey()))->toBe([])
        ->and(app(PasskeyRepository::class)->delete($admin->getKey(), 'admin-cred'))->toBeFalse();

    expect(Passkey::find('admin-cred'))->not->toBeNull();
});

it('never lets one guard\'s in-flight registration overwrite a colliding account\'s challenge', function () {
    // The registration challenge was cached at `lukk:pk:reg:{userId}` with no guard, and under
    // multi-guard `users.id === admins.id` is the ordinary case — so the second ceremony to start
    // clobbered the first, and the first then failed against a challenge it never issued.
    $user = User::factory()->create();
    $admin = Admin::factory()->create();
    expect($admin->getKey())->toBe($user->getKey());

    Lukk::useGuard('admin');
    app(PasskeyChallengeStore::class)->putForUser($admin->getKey(), 'ADMIN-CHALLENGE');
    Lukk::useGuard(null);
    app(PasskeyChallengeStore::class)->putForUser($user->getKey(), 'USER-CHALLENGE');

    expect(app(PasskeyChallengeStore::class)->pullForUser($user->getKey()))->toBe('USER-CHALLENGE');

    Lukk::useGuard('admin');
    expect(app(PasskeyChallengeStore::class)->pullForUser($admin->getKey()))->toBe('ADMIN-CHALLENGE');
    Lukk::useGuard(null);
});

it('skips a guard whose provider lives on another connection rather than sweeping it', function () {
    // A subquery cannot cross connections: the bare table name resolves against the PASSKEYS
    // connection, which either throws — aborting every guard still queued behind it — or silently
    // matches a same-named table there and reads every live credential as orphaned.
    $admin = Admin::factory()->create();
    Lukk::useGuard('admin');
    app(PasskeyRepository::class)->store($admin->getKey(), new NewPasskey('admin-cred', 'cose', 0), 'Admin Yubikey');
    Lukk::useGuard(null);

    // A genuinely SEPARATE database — its own sqlite :memory: — holding the admin directory. The
    // passkeys connection has no `directory_admins` at all, which is the whole point: an unskipped
    // subquery reaches for it there and throws.
    config([
        'database.connections.other' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => ''],
        'auth.providers.admins.model' => OtherConnectionAdmin::class,
    ]);
    Schema::connection('other')->create('directory_admins', function (Blueprint $table) {
        $table->id();
        $table->string('email')->unique();
    });
    DB::connection('other')->table('directory_admins')->insert(['id' => $admin->getKey(), 'email' => 'dir@example.test']);

    // Nothing swept for that guard — and, just as importantly, the default guard's sweep still ran
    // rather than being aborted by an exception thrown mid-loop.
    expect(app(PasskeyRepository::class)->pruneOrphaned())->toBe(0)
        ->and(Passkey::find('admin-cred'))->not->toBeNull();
});

it('sees a credential id taken by another guard, because the unique index is global', function () {
    // `credential_id` is the PRIMARY KEY — global by construction — while `findByCredentialId` is
    // guard-scoped because it is the assertion lookup. Registration therefore has to ask a wider
    // question than that lookup answers: using the scoped one, a duplicate held by another guard
    // sailed past the pre-check and hit the raw unique-constraint violation the check exists to
    // convert, turning a 422 into a 500 and leaking a cross-guard existence oracle in the process.
    $admin = Admin::factory()->create();
    Lukk::useGuard('admin');
    app(PasskeyRepository::class)->store($admin->getKey(), new NewPasskey('taken-elsewhere', 'cose', 0), 'Admin Yubikey');
    Lukk::useGuard(null);

    // Scoped: invisible, and that is correct — this guard must never ASSERT it.
    expect(app(PasskeyRepository::class)->findByCredentialId('taken-elsewhere'))->toBeNull()
        // Unscoped: visible, and that is also correct — this guard must never REGISTER over it.
        ->and(app(PasskeyRepository::class)->existsByCredentialId('taken-elsewhere'))->toBeTrue();
});

it('leaves a row it cannot attribute alone, rather than sweeping it', function () {
    // The claim UPGRADE.md leans on three times ("deliberately never deleted") and nothing asserted.
    // A NULL-guard row predates the column; under multi-guard no guard claims it, so no guard's
    // provider table can judge it. Sweeping it would destroy a live account's credential on exactly
    // the installs mid-upgrade — the ones least able to notice.
    $admin = Admin::factory()->create();
    Lukk::useGuard('admin');
    app(PasskeyRepository::class)->store($admin->getKey(), new NewPasskey('legacy-cred', 'cose', 0), 'Pre-0.6 key');
    Lukk::useGuard(null);

    // Blank the guard, exactly as a row written before the column would look.
    Passkey::whereKey('legacy-cred')->update(['guard' => null]);

    expect(app(PasskeyRepository::class)->pruneOrphaned())->toBe(0)
        ->and(Passkey::find('legacy-cred'))->not->toBeNull();
});

it('sweeps nothing at all on a multi-guard install that has not added the column yet', function () {
    // Treating a missing column as "single-guard" ran ONE unscoped pass against only the default
    // provider's table, so every other guard's credential was orphaned by construction — the exact
    // bug the column exists to fix, reintroduced in the pre-column path, on a `->daily()`
    // irreversible command. Such an install is mid-upgrade, not single-guard.
    $admin = Admin::factory()->create();
    Lukk::useGuard('admin');
    app(PasskeyRepository::class)->store($admin->getKey(), new NewPasskey('admin-cred', 'cose', 0), 'Live admin key');
    Lukk::useGuard(null);

    Schema::table('passkeys', fn (Blueprint $table) => $table->dropColumn('guard'));

    expect(app(PasskeyRepository::class)->pruneOrphaned())->toBe(0)
        ->and(Passkey::find('admin-cred'))->not->toBeNull();
});
