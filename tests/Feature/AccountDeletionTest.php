<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Lukk\Actions\DeleteAccount;
use Lukk\Actions\ExportAccount;
use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Events\AccountDeleted;
use Lukk\Events\AccountDeleting;
use Lukk\Http\Middleware\RequirePinnedAbility;
use Lukk\Lukk;
use Lukk\Models\Lockout;
use Lukk\Models\RefreshToken;
use Lukk\Tests\Fixtures\User;

uses()->group('account-deletion');

function deleteAccount(): DeleteAccount
{
    return app(DeleteAccount::class);
}

it('erases every artifact lukk owns for the user', function () {
    $user = User::factory()->create();
    $user->startSession();
    $user->startSession();

    expect(RefreshToken::where('user_id', $user->getKey())->count())->toBe(2);

    deleteAccount()($user);

    expect(RefreshToken::where('user_id', $user->getKey())->count())->toBe(0)
        ->and(User::find($user->getKey()))->toBeNull();
});

it('clears lockout counters, which are keyed by the identifier and not by user id', function () {
    // The trap the roadmap sketch missed: nothing else in the erasure path can find these, because
    // `user_id` never appears on them. Read the identifier after the row is gone and the counters —
    // rows that still name a person who asked to be forgotten — are unreachable forever.
    config(['lukk.features.lockout' => true]);
    $user = User::factory()->create(['email' => 'erase-me@example.test']);

    // Driven through the REAL flows, not hand-written subjects. An earlier version of this test
    // called `recordFailure('login', $email, null)` directly — a subject shape the application never
    // produces — so it passed while the sweep matched nothing: `lockoutSubject()` prefixes `id:` for
    // a resolvable account and `idn:` otherwise, and stamps the active guard, none of which a
    // hand-written subject exercises.
    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'wrong']);
    app('auth')->forgetGuards();
    $this->withToken($user->startSession()->accessToken)
        ->postJson('/auth/confirm-password', ['password' => 'wrong']);

    expect(Lockout::count())->toBeGreaterThanOrEqual(2)
        ->and(Lockout::pluck('subject')->all())->toContain('id:'.$user->getKey(), (string) $user->getKey());

    app('auth')->forgetGuards();
    deleteAccount()($user->refresh());

    expect(Lockout::count())->toBe(0);
});

it('kills live access tokens before it deletes anything', function () {
    // Revocation goes through the denylist first, which is the authoritative signal across nodes.
    // So even if a later step fails, the account is already unreachable rather than half-erased and
    // still usable.
    $user = User::factory()->create();
    $pair = $user->startSession();

    deleteAccount()($user);
    app('auth')->forgetGuards();

    expect(verifier()->verify($pair->accessToken))->toBeNull();
});

it('fires AccountDeleting with the intact user, and AccountDeleted after the fact', function () {
    // REAL listeners, not `Event::fake`. The fake swallows the dispatch, so it can prove an event
    // fired but nothing about WHEN — and "after the fact" is the whole reason `AccountDeleted`
    // exists separately from `AccountDeleting`. Moving the dispatch inside the transaction left the
    // faked version of this test green.
    $user = User::factory()->create(['email' => 'subject@example.test']);

    // The SUITE already runs each test in a transaction, so depth 0 is never the baseline here —
    // compare against whatever it actually is rather than a literal.
    $baseline = DB::transactionLevel();
    $deleting = $deleted = null;

    Event::listen(AccountDeleting::class, function (AccountDeleting $e) use (&$deleting) {
        $deleting = [
            'key' => $e->user->getKey(),
            // The model is still whole here — that is the documented contract, and the last chance a
            // listener has to read anything off the row.
            'identifier' => $e->user->email,
            'level' => DB::transactionLevel(),
        ];
    });

    Event::listen(AccountDeleted::class, function (AccountDeleted $e) use (&$deleted, $user) {
        $deleted = [
            'userId' => $e->userId,
            'identifier' => $e->identifier,
            // Identifiers, not the model: the row is gone, and handing a listener a deleted Eloquent
            // instance invites someone to `save()` it back.
            'carriesModel' => property_exists($e, 'user'),
            'level' => DB::transactionLevel(),
            'rowGone' => User::find($user->getKey()) === null,
        ];
    });

    deleteAccount()($user);

    expect($deleting['key'])->toBe($user->getKey())
        ->and($deleting['identifier'])->toBe('subject@example.test')
        ->and($deleting['level'])->toBeGreaterThan($baseline)  // INSIDE the transaction
        ->and($deleted['userId'])->toBe($user->getKey())
        ->and($deleted['identifier'])->toBe('subject@example.test')
        ->and($deleted['carriesModel'])->toBeFalse()
        ->and($deleted['level'])->toBe($baseline)              // AFTER the commit
        ->and($deleted['rowGone'])->toBeTrue();
});

it('rolls the whole erasure back when an app listener throws', function () {
    // A partial erasure is the bad outcome: an account with no credentials that still exists cannot
    // log in, cannot be recovered, and cannot be erased again.
    Event::listen(AccountDeleting::class, fn () => throw new RuntimeException('domain erasure failed'));

    $user = User::factory()->create();
    $pair = $user->startSession();

    expect(fn () => deleteAccount()($user))->toThrow(RuntimeException::class, 'domain erasure failed');

    expect(User::find($user->getKey()))->not->toBeNull()
        ->and(RefreshToken::where('user_id', $user->getKey())->count())->toBe(1);

    // ...but the REVOCATION is not rolled back, and that is deliberate rather than an oversight:
    // `RevokeAllSessions` runs before the transaction opens so that a failure later still leaves the
    // account unreachable rather than half-erased and still usable. The cost is that a buggy app
    // listener turns "delete my account" into "log me out of every device, permanently" — asserted
    // here because the earlier version of this test checked only what survived, which reads as a
    // clean all-or-nothing that the code does not actually provide.
    expect(RefreshToken::where('user_id', $user->getKey())->whereNull('revoked_at')->count())->toBe(0)
        ->and(verifier()->verify($pair->accessToken))->toBeNull();
});

it('lets an app anonymize instead of deleting', function () {
    Lukk::deleteUserUsing(function (User $user) {
        // What a real anonymization must remember: the two-factor columns live ON this row, so a
        // survivor keeps a working authenticator unless they are cleared here.
        $user->forceFill([
            'email' => 'anonymized-'.$user->getKey().'@example.invalid',
            'name' => 'Deleted user',
            'two_factor_secret' => null,
            'two_factor_recovery_codes' => null,
            'two_factor_confirmed_at' => null,
        ])->save();
    });

    $user = User::factory()->create(['email' => 'real@example.test']);
    $user->startSession();

    deleteAccount()($user);

    $survivor = User::find($user->getKey());

    expect($survivor)->not->toBeNull()
        ->and($survivor->email)->toStartWith('anonymized-')
        ->and(RefreshToken::where('user_id', $user->getKey())->count())->toBe(0);
});

it('erases over HTTP once the caller has stepped up', function () {
    $user = User::factory()->create();
    $pair = $user->startSession();
    $headers = confirmedHeaders($pair->accessToken);

    app('auth')->forgetGuards();
    $this->withToken($pair->accessToken)->deleteJson('/auth/account', [], $headers)->assertNoContent();

    expect(User::find($user->getKey()))->toBeNull();
});

it('refuses erasure to a caller who has only authenticated', function () {
    // Irreversible, so a stolen access token alone must not be enough — the same reasoning that
    // puts step-up in front of changing a password or removing a second factor.
    $user = User::factory()->create();

    $this->withToken($user->startSession()->accessToken)
        ->deleteJson('/auth/account')
        ->assertStatus(423);

    expect(User::find($user->getKey()))->not->toBeNull();
});

it('refuses a machine token that cannot even earn a confirmation', function () {
    // This test used to assert that step-up ALONE closed the route to machine tokens, and it passed
    // only because its pin lacked `lukk.account` — so it never exercised the boundary it claimed to.
    // Two sibling tests below cover the cases it missed: a pin that CAN earn a confirmation, and a
    // pin that borrows the human's.
    $user = User::factory()->create();
    $pat = start()($user->getKey(), [], ['ci.deploy']);

    $this->withToken($pat->accessToken)
        ->postJson('/auth/confirm-password', ['password' => 'password'])
        ->assertStatus(403);

    app('auth')->forgetGuards();
    $this->withToken($pat->accessToken)->deleteJson('/auth/account')->assertStatus(403);

    expect(User::find($user->getKey()))->not->toBeNull();
});

it('refuses a machine token that borrowed the human session\'s confirmation', function () {
    // Step-up alone does NOT close these routes to machine tokens, contrary to what the design
    // originally claimed: `RequireConfirmation` binds a confirmation to the SUBJECT, not to the
    // token that earned it, so a pin carrying nothing can present one the human's session earned.
    // The pin carries `lukk.account.delete` DELIBERATELY. An earlier version used `['ci.deploy']`
    // and asserted 403 — but 403 is the ability gate, which sorts first, so the test stayed green
    // with the session binding entirely removed. It asserted the wrong control, in exactly the way
    // the comment three tests above warns about.
    $user = User::factory()->create();
    $human = $user->startSession();
    $pat = start()($user->getKey(), [], ['lukk.account.delete']);

    $borrowed = $this->withToken($human->accessToken)
        ->postJson('/auth/confirm-password', ['password' => 'password'])->json('confirmation_token');
    app('auth')->forgetGuards();

    $this->withToken($pat->accessToken)
        ->deleteJson('/auth/account', [], ['X-Lukk-Confirmation' => $borrowed])
        ->assertStatus(423)
        ->assertJsonPath('reason', 'confirmation_session_mismatch');

    expect(User::find($user->getKey()))->not->toBeNull();
});

it('refuses a machine token pinned to lukk.account, which is not lukk.account.delete', function () {
    // `lukk.account` already meant "manage my credentials". Folding erasure into it would have handed
    // every already-issued token carrying it the power to destroy the account, silently, on upgrade
    // — and inverted the ordering, since such a token cannot revoke even one other session.
    $user = User::factory()->create();
    $pat = start()($user->getKey(), [], ['lukk.account']);

    $token = $this->withToken($pat->accessToken)
        ->postJson('/auth/confirm-password', ['password' => 'password'])->json('confirmation_token');
    app('auth')->forgetGuards();

    $this->withToken($pat->accessToken)
        ->deleteJson('/auth/account', [], ['X-Lukk-Confirmation' => $token])
        ->assertStatus(403);

    expect(User::find($user->getKey()))->not->toBeNull();
});

it('lets a machine token pinned to lukk.account.delete through', function () {
    $user = User::factory()->create();
    $pat = start()($user->getKey(), [], ['lukk.account', 'lukk.account.delete']);

    $token = $this->withToken($pat->accessToken)
        ->postJson('/auth/confirm-password', ['password' => 'password'])->json('confirmation_token');
    app('auth')->forgetGuards();

    $this->withToken($pat->accessToken)
        ->deleteJson('/auth/account', [], ['X-Lukk-Confirmation' => $token])
        ->assertNoContent();
});

it('erases artifacts written while a feature was on, even after it is switched off', function () {
    // The repositories used to be injected as null when a flag was off, which is this package's
    // "feature off" idiom everywhere else. Erasure is about rows that EXIST: a feature switched off
    // after use left its rows orphaned while the user row itself was deleted.
    config(['lukk.features.lockout' => true]);
    $user = User::factory()->create();
    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'wrong']);

    expect(Lockout::count())->toBeGreaterThan(0);

    config(['lukk.features.lockout' => false]);   // switched off AFTER the rows exist
    app('auth')->forgetGuards();

    deleteAccount()($user->refresh());

    expect(Lockout::count())->toBe(0);
});

it('does not sweep every lockout row when handed nothing to sweep', function () {
    // `forget([])` must be a no-op, not an unbounded delete. It is reachable directly — the contract
    // is public — and an empty `whereIn` would otherwise match the whole table on some drivers.
    config(['lukk.features.lockout' => true]);
    $user = User::factory()->create();
    $this->postJson('/auth/login', ['email' => $user->email, 'password' => 'wrong']);

    $before = Lockout::count();
    expect($before)->toBeGreaterThan(0);

    expect(app(LockoutRepository::class)->forget([], null))->toBe(0)
        ->and(app(LockoutRepository::class)->forget(['', ''], 'api'))->toBe(0)
        ->and(Lockout::count())->toBe($before);
});

it('skips orphan pruning rather than guessing when the provider has no model', function () {
    // A non-Eloquent provider has no table to compare against. Deleting on a failed lookup would
    // erase every passkey in the install, so this must fail closed by doing nothing.
    config(['auth.providers.users' => ['driver' => 'custom-non-eloquent']]);

    expect(app(PasskeyRepository::class)->pruneOrphaned())->toBe(0);
});

it('prunes without a passkeys table, which most installs do not have', function () {
    // Passkeys are opt-in with a publish-only migration, and `lukk:prune` is SCHEDULED DAILY by
    // default — so throwing here broke the scheduled prune for every install that never enabled
    // them, taking the refresh-token and lockout sweeps down with it.
    Schema::drop('passkeys');

    command('lukk:prune')->assertSuccessful();
});

it('re-reads the schema rather than caching it for the life of the process', function () {
    // A static memo is answered once per PROCESS: a worker started before a migration keeps saying
    // "no such table" and silently skips erasing those rows — the one failure mode erasure exists to
    // prevent — and it leaks between tests in a shared process.
    $user = User::factory()->create();
    Schema::drop('lukk_lockouts');

    deleteAccount()($user);   // must not throw with the table absent

    // Mirrors database/lockout/*.php — a ULID key, not an auto-increment.
    Schema::create('lukk_lockouts', function (Blueprint $table) {
        $table->ulid('id')->primary();
        $table->string('purpose', 32);
        $table->string('subject');
        $table->string('guard', 64)->default('');
        $table->unsignedInteger('attempts')->default(0);
        $table->timestamp('locked_at')->nullable();
        $table->timestamps();
        $table->unique(['purpose', 'subject', 'guard']);
    });

    $second = User::factory()->create();
    app(LockoutRepository::class)->recordFailure('confirm', (string) $second->getKey(), 'api');
    expect(Lockout::count())->toBe(1);

    app('auth')->forgetGuards();
    deleteAccount()($second);

    expect(Lockout::count())->toBe(0);   // the memo would have skipped this
});

it('sweeps the pending password-reset row, which nothing else garbage-collects', function () {
    // Laravel does not schedule `deleteExpired`, so this row keeps a PLAINTEXT email address of
    // someone who asked to be forgotten for as long as the table lives — Art. 17 in the most literal
    // sense. The sweep was entirely unpinned before this test.
    config(['lukk.features.password_reset' => true]);
    $user = User::factory()->create(['email' => 'sweep@example.test']);
    Password::broker()->createToken($user);
    expect(DB::table('password_reset_tokens')->count())->toBe(1);

    app(DeleteAccount::class)($user);

    expect(DB::table('password_reset_tokens')->count())->toBe(0);
});

it('sweeps the CONFIGURED broker, not whatever the default one points at', function () {
    // `SendPasswordResetLink` and `ResetPassword` both honour `lukk.password_reset.broker`; erasure
    // called `Password::broker()` with no argument, so it was wrong in both directions at once — the
    // subject's real row survived, and the delete landed on the default broker's table, keyed on
    // email alone, which under multi-guard is shared.
    Schema::create('lukk_password_resets', function (Blueprint $table) {
        $table->string('email')->primary();
        $table->string('token');
        $table->timestamp('created_at')->nullable();
    });
    config([
        'auth.passwords.lukkbroker' => ['provider' => 'users', 'table' => 'lukk_password_resets', 'expire' => 60],
        'lukk.features.password_reset' => true,
        'lukk.password_reset.broker' => 'lukkbroker',
    ]);

    $user = User::factory()->create(['email' => 'broker@example.test']);
    Password::broker('lukkbroker')->createToken($user);
    expect(DB::table('lukk_password_resets')->count())->toBe(1);

    app(DeleteAccount::class)($user);

    expect(DB::table('lukk_password_resets')->count())->toBe(0);
});

it('keeps the erasure gate even when gate_auth_routes is switched off', function () {
    // `gate_auth_routes = false` is the documented opt-out that buys back pre-0.6 reach for tokens
    // issued before abilities existed. Erasure did not exist then, so honouring the flag here would
    // not restore an old behaviour — it would let a `['ci.deploy']` token earn its own confirmation
    // and destroy the account, arriving on upgrade with no re-consent.
    config(['lukk.features.gate_auth_routes' => false]);
    $user = User::factory()->create();
    $pat = start()($user->getKey(), [], ['ci.deploy']);

    $confirmation = $this->withToken($pat->accessToken)
        ->postJson('/auth/confirm-password', ['password' => 'password'])->json('confirmation_token');
    app('auth')->forgetGuards();

    $this->withToken($pat->accessToken)
        ->deleteJson('/auth/account', [], ['X-Lukk-Confirmation' => $confirmation])
        ->assertStatus(403);
    app('auth')->forgetGuards();

    $this->withToken($pat->accessToken)
        ->getJson('/auth/account/export', ['X-Lukk-Confirmation' => $confirmation])
        ->assertStatus(403);

    expect(User::find($user->getKey()))->not->toBeNull();
});

it('still refuses a gate that names no real ability', function () {
    // `ALWAYS` is a marker, not an ability — a route declaring only the marker has no gate at all,
    // and must fail loudly at request time rather than silently admitting every pinned token.
    $this->withoutExceptionHandling();
    Route::middleware(['auth:api', RequirePinnedAbility::class.':'.RequirePinnedAbility::ALWAYS])
        ->get('/marker-only', fn () => response()->noContent());

    $user = User::factory()->create();
    $pat = start()($user->getKey(), [], ['ci.deploy']);

    expect(fn () => $this->withToken($pat->accessToken)->getJson('/marker-only'))
        ->toThrow(InvalidArgumentException::class);
});

it('clears the idn: lockout counter, the one that outlives the user row', function () {
    // THE reason the identifier is captured before anything is deleted — and it was unpinned:
    // deleting the `idn:` element from the sweep left the whole suite green. The sibling test above
    // fails a login for an address that RESOLVES to an account, so `lockoutSubject()` returns
    // `id:<userId>` and the `idn:` space is never created at all.
    //
    // This space is reachable only through the identifier, because `user_id` never appears on the
    // row. Miss it and a counter naming a person who asked to be forgotten survives permanently —
    // `prune()` never removes a held lock at any age.
    config(['lukk.features.lockout' => true]);

    // Fail a login for an address with NO account: that is what produces `idn:<normalized>`.
    $this->postJson('/auth/login', ['email' => 'later-me@example.test', 'password' => 'wrong']);
    expect(Lockout::pluck('subject')->all())->toContain('idn:later-me@example.test');

    // ...then that address registers. The counter is still keyed by identifier, not by the new id.
    $user = User::factory()->create(['email' => 'later-me@example.test']);
    app('auth')->forgetGuards();

    deleteAccount()($user);

    expect(Lockout::where('subject', 'idn:later-me@example.test')->count())->toBe(0)
        ->and(Lockout::count())->toBe(0);
});

it('erases without a passkeys table, which most installs do not have', function () {
    // Passkeys are opt-in with a publish-only migration, so NO table is the common case — and both
    // the erasure guard and the export guard were unpinned, so removing either left the suite green
    // while erasing or exporting on an ordinary install 500'd.
    Schema::drop('passkeys');
    $user = User::factory()->create();

    deleteAccount()($user);

    expect(User::find($user->getKey()))->toBeNull();
});

it('exports without a passkeys table', function () {
    Schema::drop('passkeys');
    $user = User::factory()->create();
    $user->startSession();

    $export = app(ExportAccount::class)($user);

    expect($export['passkeys'])->toBe([])
        ->and($export['sessions'])->toHaveCount(1);
});

it('meters the export, which is the widest read lukk offers', function () {
    // Nine lines of rationale sit above this middleware and nothing asserted it. `lukk-confirm` is
    // 5/60s, so the sixth call in a window is refused.
    config(['lukk.features.lockout' => false]);
    $user = User::factory()->create();
    $pair = $user->startSession();

    $confirmation = $this->withToken($pair->accessToken)
        ->postJson('/auth/confirm-password', ['password' => 'password'])->json('confirmation_token');

    $statuses = [];
    for ($i = 0; $i < 8; $i++) {
        app('auth')->forgetGuards();
        $statuses[] = $this->withToken($pair->accessToken)
            ->getJson('/auth/account/export', ['X-Lukk-Confirmation' => $confirmation])->status();
    }

    expect($statuses)->toContain(429);
});

it('forgets nothing, without erroring, on an install that never migrated lockouts', function () {
    // `forget()` was the only public method on the lockout repository with no table guard — safe
    // purely because its one call site in `DeleteAccount` happens to check first. The contract is
    // public, and the lockout migration is publish-only, so a consumer calling it directly on an
    // install that never opted in got a raw SQL error.
    Schema::drop('lukk_lockouts');

    expect(app(LockoutRepository::class)->forget(['id:1'], 'api'))->toBe(0);
});
