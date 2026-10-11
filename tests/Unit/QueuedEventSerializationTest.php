<?php

declare(strict_types=1);

use Illuminate\Contracts\Database\ModelIdentifier;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Events\CallQueuedListener;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Lukk\Events\PasskeyDeleted;
use Lukk\Events\PasskeyRegistered;
use Lukk\Events\PasswordChanged;
use Lukk\Events\RecoveryCodesGenerated;
use Lukk\Events\RecoveryCodeUsed;
use Lukk\Events\TwoFactorAuthenticationConfirmed;
use Lukk\Events\TwoFactorAuthenticationDisabled;
use Lukk\Tests\Fixtures\User;

/*
 * These events carry the user, and the docs encourage a QUEUED listener to tell them ("your password was
 * changed"). Without `SerializesModels` the whole model went into `jobs.payload` — and on a failure into
 * `failed_jobs`, kept indefinitely: the password hash, the encrypted TOTP secret, the recovery-code
 * hashes. Laravel's own `PasswordReset` and `Verified` carry the user the same way and serialize it as an
 * identifier, re-read when the job runs.
 */

class NotifiesUserOfAuthenticatorChange implements ShouldQueue
{
    public function handle(object $event): void {}
}

function userWithSecrets(): User
{
    $user = User::factory()->create();
    $user->forceFill([
        'two_factor_secret' => Crypt::encryptString('JBSWY3DPEHPK3PXP'),
        'two_factor_recovery_codes' => json_encode(['$2y$04$recoverycodehashrecoverycodehashrecoverycodehash']),
        'two_factor_confirmed_at' => now(),
    ])->save();

    return $user;
}

dataset('user events', [
    'PasswordChanged' => [fn (User $u) => new PasswordChanged($u)],
    'TwoFactorAuthenticationConfirmed' => [fn (User $u) => new TwoFactorAuthenticationConfirmed($u)],
    'TwoFactorAuthenticationDisabled' => [fn (User $u) => new TwoFactorAuthenticationDisabled($u)],
    'RecoveryCodesGenerated' => [fn (User $u) => new RecoveryCodesGenerated($u)],
    'RecoveryCodeUsed' => [fn (User $u) => new RecoveryCodeUsed($u, 7)],
    'PasskeyRegistered' => [fn (User $u) => new PasskeyRegistered($u, 'cred-1', 'phone')],
    'PasskeyDeleted' => [fn (User $u) => new PasskeyDeleted($u, 'cred-1')],
]);

it('queues the user as an identifier, never the model with its secrets', function (Closure $make) {
    $user = userWithSecrets();
    $payload = serialize($make($user));

    expect($payload)->toContain(ModelIdentifier::class)
        ->and($payload)->not->toContain($user->password)
        ->and($payload)->not->toContain($user->two_factor_secret)
        ->and($payload)->not->toContain('recoverycodehash');

    $restored = unserialize($payload);
    expect($restored->user)->toBeInstanceOf(User::class)
        ->and($restored->user->getKey())->toBe($user->getKey());
})->with('user events');

it('keeps a queued listener\'s job free of the user\'s secrets', function () {
    Queue::fake();
    Event::listen(PasswordChanged::class, NotifiesUserOfAuthenticatorChange::class);
    $user = userWithSecrets();

    event(new PasswordChanged($user));

    Queue::assertPushed(CallQueuedListener::class, function (CallQueuedListener $job) use ($user) {
        $payload = serialize($job);

        return str_contains($payload, ModelIdentifier::class) && ! str_contains($payload, $user->password);
    });
});
