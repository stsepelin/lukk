<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Schema;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Events\AccountDeleted;
use Lukk\Events\AccountDeleting;
use Lukk\Lukk;

/**
 * Erase an account: lukk's own artifacts, then the user itself (GDPR Art. 17).
 *
 * ORDER MATTERS, and each step is placed for a reason:
 *
 *  1. **Capture the identifier first.** Lockout counters are keyed by the normalized identifier —
 *     an email address — not by `user_id`. Read it after the row is gone and those counters are
 *     unreachable forever, leaving rows that still name someone who asked to be forgotten.
 *  2. **Revoke sessions before deleting anything.** `RevokeAllSessions` writes the denylist first,
 *     which is the authoritative early signal across every node. Every access token dies now, not
 *     when the rows happen to disappear — so a failure later in this method still leaves the
 *     account unreachable rather than half-erased and still usable.
 *  3. **Everything else inside ONE transaction**, including the application's `AccountDeleting`
 *     listener and the delete callback. A partial erasure is the bad outcome here: an account with
 *     no credentials that still exists cannot log in, cannot be recovered, and cannot be erased
 *     again. Running consumer code inside a transaction is normally something this package avoids
 *     (see `RotateRefreshToken`), and the trade is deliberately opposite here: erasure is a rare,
 *     one-shot, irreversible operation where atomicity beats lock duration.
 *  4. **`AccountDeleted` after the commit**, so a listener that talks to a downstream processor
 *     cannot roll the erasure back — and cannot be rolled back itself, having already told someone
 *     else to delete their copy.
 *
 * **The atomicity in step 3 is per-connection.** SQL has no cross-connection transaction without
 * two-phase commit, so if the provider model, `passkeys` or the broker's table live on a different
 * connection than lukk's own, "one transaction" is really one per connection. `disposeOf()` gives
 * the user's connection its own, which covers every failure raised inside the erasure; a failure
 * during the commit sequence itself can still diverge. The surviving state is the one this class
 * prefers throughout — unreachable rather than half-erased and still usable — but the leftover rows
 * are real, and `lukk:prune` is what sweeps them.
 */
class DeleteAccount
{
    public function __construct(
        private readonly RefreshTokenRepository $tokens,
        private readonly RevokeAllSessions $revokeAllSessions,
        private readonly PasskeyRepository $passkeys,
        private readonly LockoutRepository $lockouts,
        private readonly string $identifierColumn,
        private readonly string $guard,
        /**
         * The broker whose table holds this guard's reset rows.
         *
         * `Password::broker()` with no argument is the DEFAULT broker, which on an install that
         * configures `lukk.password_reset.broker` is the wrong table twice over: the subject's
         * pending reset row survives erasure (the row this sweep exists for — it holds a plaintext
         * address), while the delete lands on whatever table the default broker points at, keyed on
         * email alone, which under multi-guard is shared. `SendPasswordResetLink` and `ResetPassword`
         * both already honour this setting; the erasure path was the one that did not.
         */
        private readonly ?string $passwordBroker = null,
    ) {}

    public function __invoke(Authenticatable $user): void
    {
        $userId = $user->getAuthIdentifier();
        $identifier = $this->identifierOf($user);

        ($this->revokeAllSessions)($userId);

        $this->tokens->transaction(function () use ($user, $userId, $identifier): void {
            event(new AccountDeleting($user, $this->guard));

            $this->tokens->deleteForUser($userId);

            // Guarded on the TABLE, not on the feature flag. A feature switched off after use leaves
            // its rows behind, and those rows are still personal data — a passkey carries a
            // human-chosen device name and a last-used timestamp. An install that never published
            // the migration has no table, and that is the only case worth skipping.
            if ($this->tableExists('passkeys')) {
                $this->passkeys->deleteForUser($userId);
            }

            // All THREE key spaces a single account occupies. The raw identifier is never one of
            // them — `LoginRateLimiter::lockoutSubject()` prefixes `id:` for a resolvable account
            // and `idn:` for one that resolves to nothing — so an earlier sweep keyed on the raw
            // value matched no real row at all, and only looked correct because its test hand-wrote
            // a subject that bypassed the derivation. `prune()` never removes a held lock at any
            // age, so anything missed here is permanent.
            if ($this->tableExists('lukk_lockouts')) {
                $this->lockouts->forget([
                    LoginRateLimiter::lockoutSubject($user, ''),              // id:<userId>   — login
                    (string) $userId,                                         // <userId>      — confirm / two-factor
                    $identifier === null ? '' : LoginRateLimiter::lockoutSubject(null, $identifier), // idn:<normalized>
                ], $this->guard);
            }

            // The password broker's own table. Laravel does not garbage-collect it by default
            // (`deleteExpired` is not scheduled), so a pending reset row keeps a plaintext email
            // address of someone who asked to be forgotten for as long as the table lives.
            // Guarded on the TABLE, not on `features.password_reset` — the same rule as the passkey
            // and lockout sweeps three lines up, and it was the one sweep that broke it. Switching
            // the feature off does not delete the rows it already wrote, and this row is the single
            // artifact holding a PLAINTEXT email address of someone who asked to be forgotten. An
            // install that never ran the broker's migration has no table, and that is the only case
            // worth skipping.
            if ($user instanceof CanResetPassword && $this->tableExists($this->passwordResetTable())) {
                Password::broker($this->passwordBroker)->deleteToken($user);
            }

            // Two-factor material lives in columns ON the user row, so deleting the row takes it.
            // An app that anonymizes instead of deleting must clear them itself — the callback is
            // the only thing that knows the row survives, so it is the only thing that can.
            $this->disposeOf($user);
        });

        event(new AccountDeleted($userId, $identifier, $this->guard));
    }

    /**
     * Deliberately NOT memoized.
     *
     * A static cache looked free — schema state, on a rare path — but it is answered once per
     * PROCESS: a worker that started before a migration keeps saying "no such table" and silently
     * skips erasing those rows, which is the one failure mode this method exists to prevent. It also
     * leaks between tests in a shared process. Two cheap queries on an irreversible operation is not
     * a cost worth that.
     */
    private function tableExists(string $table): bool
    {
        return Schema::hasTable($table);
    }

    /**
     * The table the configured broker actually writes to.
     *
     * Not hardcoded `password_reset_tokens`: a broker may name its own (`lukk.password_reset.broker`
     * pointing at one with `'table' => 'lukk_password_resets'` is exactly the setup the sibling
     * regression test uses), and guarding on the wrong name would skip a sweep that had work to do.
     */
    private function passwordResetTable(): string
    {
        $broker = $this->passwordBroker ?? (string) config('auth.defaults.passwords');

        return (string) (config("auth.passwords.{$broker}.table") ?? 'password_reset_tokens');
    }

    /**
     * Run the disposal inside a transaction on the USER's own connection.
     *
     * The surrounding transaction belongs to lukk's connection. When the provider model lives on a
     * different one — identities in a shared directory database, application tables local — the
     * disposal ran with no transaction at all: it committed the moment it executed, so a rollback
     * afterwards restored the refresh tokens, passkeys, lockouts and reset row around a user that
     * was already permanently gone. The callback is application code and is documented as
     * ANONYMIZING (several writes, not one), so failing halfway is its most likely failure, not its
     * least.
     *
     * On a single connection this nests, which Laravel implements as a SAVEPOINT — semantics
     * unchanged. It is written without a same-connection branch on purpose: a branch here would be
     * exercised only by the rare topology and would rot untested.
     *
     * **This does not make erasure atomic across connections, and nothing can** — that needs
     * two-phase commit. What it closes is every failure raised INSIDE the erasure: both transactions
     * roll back. What remains is a failure during the commit sequence itself, where the inner
     * connection has committed and the outer then fails. The surviving state is the one this class
     * already prefers everywhere else — the account is unreachable rather than half-erased and still
     * usable — but the leftover rows are real, and `lukk:prune` is what sweeps them.
     */
    private function disposeOf(Authenticatable $user): void
    {
        $disposal = Lukk::$deleteUserUsing ?? self::defaultDisposal(...);

        // A consumer's provider need not be Eloquent, and a non-Eloquent user has no connection to
        // open a transaction on. Nothing to nest — run it as before.
        if (! $user instanceof Model) {
            $disposal($user);

            return;
        }

        $user->getConnection()->transaction(fn () => $disposal($user));
    }

    /**
     * Erase the row, and mean it.
     *
     * `delete()` on a `SoftDeletes` model is a silent no-op for Art. 17: name, email, password hash,
     * encrypted TOTP secret and recovery codes all remain, and the subject is left neither erased
     * nor able to return — re-registering the same address hits the DB unique index, because the
     * `unique` validation rule respects the soft-delete scope and the index does not.
     *
     * `forceDelete()` is therefore the default. An app that genuinely wants the row to survive says
     * so explicitly with `Lukk::deleteUserUsing()`, which is the only place that can also clear the
     * two-factor columns a survivor would otherwise keep.
     */
    private static function defaultDisposal(Authenticatable $user): void
    {
        method_exists($user, 'forceDelete') ? $user->forceDelete() : $user->delete();
    }

    /**
     * The value the account authenticates with, read while the model is still whole.
     *
     * Nullable because a consumer's model need not expose the configured column — a passkey-only
     * user identified by something lukk was never told about. Losing the lockout sweep is the
     * documented cost of that; losing the erasure would not be acceptable.
     */
    private function identifierOf(Authenticatable $user): ?string
    {
        $value = $user->{$this->identifierColumn} ?? null;

        return is_scalar($value) ? (string) $value : null;
    }
}
