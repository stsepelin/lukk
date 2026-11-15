<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use Lukk\Lukk;
use Lukk\Support\HashablePassword;
use RuntimeException;

/**
 * Create a new user and fire Laravel's `Registered` event — so the framework's
 * email-verification listener sends the (lukk-signed) link when `features.email_verification`
 * is on and the model is `MustVerifyEmail`. Mirrors AttemptLogin: it resolves the user and
 * returns it; the controller owns the post-auth branching (2FA / verification / session).
 *
 * Creation is fully replaceable via `Lukk::registerUsing()`; the default writes `name` + the
 * identifier column (config `lukk.username`) + a hashed `password` against the configured model.
 */
class Register
{
    /**
     * @param  class-string  $model  Default user model, used only when no registerUsing hook is set.
     * @param  string  $username  The identifier column (config `lukk.username`), e.g. email or username.
     */
    public function __construct(
        private readonly string $model,
        private readonly string $username,
    ) {}

    /**
     * @param  array<string,mixed>  $payload  Validated registration input (incl. plaintext `password`).
     */
    public function __invoke(array $payload): Authenticatable
    {
        $user = $this->createUser($payload);

        event(new Registered($user));

        return $user;
    }

    /**
     * @param  array<string,mixed>  $payload
     */
    private function createUser(array $payload): Authenticatable
    {
        $factory = Lukk::$registerUsing;

        if ($factory !== null) {
            $user = is_string($factory) ? app($factory)($payload) : $factory($payload);

            if (! $user instanceof Authenticatable) {
                throw new RuntimeException('Lukk::registerUsing must return an '.Authenticatable::class.'.');
            }

            // Guard the auto-login invariant: the hook must create a NEW user, never return an
            // existing one (e.g. firstOrCreate). lukk logs in whatever it returns, so handing
            // back an existing account would be a credential-free takeover.
            if ($user instanceof Model && ! $user->wasRecentlyCreated) {
                throw new RuntimeException('Lukk::registerUsing must return a newly-created user, not an existing one.');
            }

            return $user;
        }

        // Default create: the stock Laravel shape (below). For any other shape, use registerUsing().
        foreach (['name', $this->username, 'password'] as $key) {
            if (! isset($payload[$key])) {
                throw new RuntimeException("The default registration create needs `{$key}`; use Lukk::registerUsing() for a custom user shape.");
            }
        }

        $connection = $this->model::query()->getConnection();

        try {
            // In a transaction of its own — a SAVEPOINT when the caller already holds one — so that a
            // failed INSERT leaves the connection usable for the lookup below. On PostgreSQL it otherwise
            // aborts the caller's transaction: every later statement raises 25P02, and the caller's
            // COMMIT silently becomes a ROLLBACK.
            return $connection->transaction(fn () => $this->model::create([
                'name' => $payload['name'],
                $this->username => $payload[$this->username],
                // `Hash::make` goes through the facade's untyped `__callStatic`, so a non-string is coerced
                // either way; the cast states the type.
                'password' => Hash::make(HashablePassword::normalize((string) $payload['password'])), // @pest-mutate-ignore: RemoveStringCast
            ]));
        } catch (UniqueConstraintViolationException $e) {
            // `Rule::unique` checks and the INSERT writes, and a key derivation sits between them: two
            // posts of one address (a double-clicked sign-up) both pass the rule, and the loser's INSERT
            // was a 500 where the form promises a 422. So the question the rule asked is asked again —
            // is there a row with this identifier — and answered `unique`'s way only when one now
            // EXISTS: a violation on some other unique column is the application's own and stays the
            // error it was. Asked of the table, as the rule asks it: under no model scope, so a
            // soft-deleted row holding the identifier counts, as it did for the index.
            $holder = fn () => $this->model::query()->withoutGlobalScopes()->where($this->username, $payload[$this->username]);

            if ($holder()->exists() || $this->committedSince($connection, $holder)) {
                // Validation's own message for the rule: its translation, the attribute's name, the value.
                $answer = Validator::make([$this->username => $payload[$this->username]], []);
                $answer->addFailure($this->username, 'unique');

                throw new ValidationException($answer);
            }

            throw $e;
        }
    }

    /**
     * Is there such a row among what is COMMITTED now, though this transaction's plain read saw none?
     *
     * The one case the plain read cannot reach: inside a transaction of the CALLER's that has already
     * read, on MySQL's REPEATABLE READ, it answers from that transaction's snapshot, taken before the
     * competing row was committed — it saw no row, and the violation stayed a 500. A locking read is not
     * a snapshot read there: it answers from what is committed now, which is what the index answered from.
     *
     * Only after the plain read, and never instead of it. A locking read takes a lock and needs the
     * privilege to, and on PostgreSQL at REPEATABLE READ it fails outright (40001) on a row that changed
     * since the snapshot — the very row a plain read would simply have shown. In a savepoint of its own
     * for the same reason the INSERT is: a failed statement must not cost the caller their transaction.
     * And any failure is "no answer", which leaves the violation the exception it was. (PostgreSQL at
     * REPEATABLE READ or above reads its snapshot even with a lock, so a row committed since stays
     * unseen there, and the violation stays the exception.)
     *
     * @param  \Closure(): Builder<Model>  $holder
     */
    private function committedSince(ConnectionInterface $connection, \Closure $holder): bool
    {
        try {
            return $connection->transaction(fn () => $holder()->sharedLock()->exists());
        } catch (QueryException) {
            return false;
        }
    }
}
