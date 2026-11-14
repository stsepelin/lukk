<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Auth\Passwords\PasswordBroker;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use Lukk\Actions\Concerns\CountsLockoutAttempts;
use Lukk\Actions\Concerns\ReadsPasswordBroker;
use Lukk\Actions\Concerns\ThrowsWhenLocked;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Contracts\LockoutRepository;
use Lukk\Events\PasswordChanged;
use Lukk\Lukk;
use Lukk\Support\HashablePassword;

/**
 * Change the password of an already-authenticated user, having re-verified the current one.
 *
 * The signed-in counterpart to the forgot-password flow: no email round-trip, because the caller
 * already holds a session and can prove the existing password. That proof is the whole security
 * story — a stolen access token alone must not be enough to take the account over permanently,
 * which is exactly what changing the password would do.
 *
 * So this checks the SAME secret the login route throttles twice over, and is metered the same way:
 * the route carries `lukk-confirm`, and a failed attempt counts toward the `confirm` lockout. It is
 * deliberately the same budget as step-up confirmation rather than a second one — two independent
 * allowances for guessing one password is just a larger allowance.
 *
 * Requires an ELOQUENT user model: the write is a query on the model's own table, which is not on the
 * `Authenticatable` contract. Same assumption as `ResetPassword` (and as Fortify), but worth saying
 * out loud for anyone who has swapped `lukk.user_provider` for a non-Eloquent one.
 */
class ChangePassword
{
    use CountsLockoutAttempts;
    use ReadsPasswordBroker;
    use ThrowsWhenLocked;

    public function __construct(
        private readonly UserProvider $users,
        private readonly RevokeOtherSessions $revokeOtherSessions,
        private readonly RevokeAllSessions $revokeAllSessions,
        // Null unless `features.lockout` is on.
        private readonly ?LockoutRepository $lockouts = null,
        private readonly ?string $guard = null,
        // `lukk.password_reset.broker`; null is the default broker.
        private readonly ?string $passwordBroker = null,
    ) {}

    public function __invoke(Authenticatable $user, #[\SensitiveParameter] string $current, #[\SensitiveParameter] string $password, ?string $currentFamilyId): void
    {
        $subject = (string) $user->getAuthIdentifier();

        if ($this->lockouts?->locked('confirm', $subject, $this->guard)) {
            $this->throwLocked('confirm', $subject, 'current_password');
        }

        // Reserved before the credential check, like every other password path: reading "is it
        // locked" and counting afterwards lets concurrent requests each get a guess.
        if ($this->lockouts !== null
            && $this->reserveAttempt($this->lockouts, 'confirm', $subject) > $this->lockouts->maxAttempts()) {
            $this->throwLocked('confirm', $subject, 'current_password');
        }

        // The lock lands only once the check has failed — see `CountsLockoutAttempts`.
        // The write is inside the same `try`: it checks the current password again when the stored hash
        // moved under it, and a failure there is a wrong guess like any other.
        try {
            $this->verifyCurrent($user, $current);
            $this->store($user, $current, $password);
        } catch (ValidationException $e) {
            $this->attemptFailed($this->lockouts, 'confirm', $subject);

            throw $e;
        }

        $this->forgetPendingReset($user);

        // BOTH counters. The failures they hold were against a password that no longer exists, and
        // the reset path already releases both for exactly that reason. Releasing only `confirm`
        // left a user who was being brute-forced, noticed, and did the right thing still locked out
        // of login on every other device — permanently, with `release_after` at 0 — and the only
        // way out was the reset email this endpoint exists to avoid. Safe to do here: reaching this
        // line required proving the current password.
        $this->lockouts?->release('confirm', $subject, $this->guard);
        // (The identifier argument is unused when a user is passed.)
        foreach (LoginRateLimiter::subjectsOf($user) as $subject) {
            $this->lockouts?->release('login', $subject, $this->guard);
        }

        // Every OTHER session dies; this one survives. Changing a password is what a user does when
        // they think someone else is in the account, so leaving those sessions alive would defeat
        // the point — but logging the user out of the tab they just did it in is a bad answer to a
        // good instinct. `RevokeOtherSessions` denylists before revoking, so the access tokens stop
        // working immediately rather than at the end of their TTL.
        //
        // With no family id, revoke EVERYTHING. A token carrying no `fid` was not minted by this
        // package's session flow — it comes from a co-issuer sharing the secret, the topology the
        // verify-only config documents — so there is no lukk-tracked session of the caller's among
        // these rows to protect. Skipping the sweep there returned "password-changed" while every
        // session the user believed they had just killed stayed live, and said so nowhere.
        $currentFamilyId === null
            ? ($this->revokeAllSessions)($user->getAuthIdentifier())
            : ($this->revokeOtherSessions)($user->getAuthIdentifier(), $currentFamilyId);

        event(new PasswordChanged($user));
    }

    /**
     * Write the new hash — over the password that was CHECKED, or not at all.
     *
     * The current password is verified against the hash the guard loaded when the request began. A
     * recovery reset that commits after that check and before this write used to be overwritten: the
     * owner's reset answered "password-reset", revoked every session, and a moment later the password
     * was whatever the holder of the OLD one had asked for. A reset exists to shut exactly that caller
     * out (NIST SP 800-63B-4 §4.2), and the window is as wide as two key derivations.
     *
     * So the write is ONE conditional UPDATE — `where password = <the hash that was checked>` — as the
     * sign-in rehash does it. A hash that changed is not automatically a refusal — a concurrent sign-in
     * may have rehashed the SAME password at a new cost — so the current password is checked again,
     * against what is stored now, and the write retried over that; only a failed check answers as a wrong
     * current password does.
     *
     * No transaction and no row lock, on purpose. An earlier revision locked the row and called
     * `save()` inside the transaction, which ran the application's model observers and (in the re-check)
     * a key derivation under the lock — and on PostgreSQL an observer that swallowed a failed query left
     * the transaction aborted, so `COMMIT` became `ROLLBACK`: the change answered "password-changed",
     * revoked the other sessions, and stored nothing.
     */
    private function store(Authenticatable $user, #[\SensitiveParameter] string $current, #[\SensitiveParameter] string $password): void
    {
        // Every provider lukk signs in through hands back a model here; this states the type.
        assert($user instanceof Model); // @pest-mutate-ignore: RemoveFunctionCall,InstanceOfToTrue

        // The column the model names (`getAuthPasswordName()`), as sign-in reads it.
        $column = $user->getAuthPasswordName();
        $checked = $user->getAuthPassword();
        $hash = Hash::make(HashablePassword::normalize($password));
        $row = fn () => $user->newQueryWithoutScopes()->whereKey($user->getKey());

        while ($row()->where($column, $checked)->update([$column => $hash]) !== 1) {
            // A row deleted meanwhile reads null, which no check accepts.
            $checked = $row()->value($column);

            // Already what was being written: MySQL counts rows CHANGED, not rows matched, so an UPDATE
            // that matched and set the value it found reports 0 — and retrying it would never report
            // anything else.
            if ($checked === $hash) {
                break;
            }

            $this->verifyCurrent((clone $user)->setRawAttributes([...$user->getAttributes(), $column => $checked]), $current);
        }

        $this->written($user, $column, $hash);
    }

    /**
     * Bring the model in line with the row, and tell the application's observers.
     *
     * The write was a query, not `save()`, so Eloquent fired nothing. `updated` and `saved` are fired
     * here — after the write, outside any transaction of lukk's — with the password reading as changed,
     * so an audit observer on the user model still sees a password change. `saving` and `updating` are
     * not: they run before a write and may veto or rewrite it, and this write had to be conditional.
     *
     * Through Eloquent's own `fireModelEvent()`, which is protected: it is what reaches observers,
     * closure listeners AND the classes a model maps in `$dispatchesEvents`, and naming the events by
     * hand reached only the first two.
     */
    private function written(Model $user, string $column, string $hash): void
    {
        $user->setRawAttributes([...$user->getAttributes(), $column => $hash]);
        $user->syncChanges();

        $fire = \Closure::bind(fn (string $event) => $user->fireModelEvent($event, false), null, Model::class);

        foreach (['updated', 'saved'] as $event) {
            $fire($event);
        }

        // Already stored: left dirty, a later `save()` of this instance would write it again, over a
        // reset that landed meanwhile.
        $user->syncOriginalAttribute($column);
    }

    /**
     * Drop a reset link requested before this change.
     *
     * A reset token stays valid until it expires (an hour by default) whatever happens to the password
     * meanwhile. Someone who asked for one — the owner, or whoever was in their mailbox — could let the
     * owner change the password and then undo it with the older link: the change answered
     * "password-changed" and the account was one click from a password the owner did not choose.
     *
     * Best effort, and never a reason to fail a change that has already been written: only where the
     * broker's table exists (a cache-backed broker has none to sweep, and its token simply expires), and
     * a failure is reported, not thrown.
     */
    private function forgetPendingReset(Authenticatable $user): void
    {
        try {
            if ($user instanceof CanResetPassword && $this->resetTableExists()) {
                /** @var PasswordBroker $broker */
                $broker = Password::broker($this->passwordBroker);
                $broker->deleteToken($user);
            }
        } catch (\Throwable $e) {
            report($e);
        }
    }

    private function verifyCurrent(Authenticatable $user, #[\SensitiveParameter] string $current): void
    {
        // Under each spelling of it (as typed, then normalized), each check failing closed if the stored
        // hash is one the active hasher refuses; see `HashablePassword::verified()`.
        $verified = HashablePassword::verified($this->users, $user, ['password' => $current]);

        if ($verified === null) {
            throw ValidationException::withMessages(['current_password' => [__('The provided password is incorrect.')]]);
        }

        // A bcrypt row longer than 72 bytes verifies only in part; see `HashablePassword::mustReset()`.
        if (HashablePassword::verifiesOnlyInPart($user, $verified)) {
            throw HashablePassword::mustReset('current_password');
        }
    }

    private function lockoutGuard(): ?string
    {
        return $this->guard;
    }
}
