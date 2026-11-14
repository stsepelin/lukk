<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
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
            // was a 500 where the form promises a 422. The rule is simply asked again, so it answers only
            // when a row with this identifier now EXISTS — a violation on some other unique column is
            // the application's own and stays the error it was — and in the words, translation and
            // attribute name validation would have used.
            //
            // One case it cannot reach: called inside a transaction of the CALLER's that has already read,
            // on MySQL's REPEATABLE READ, the rule reads that transaction's snapshot, does not see the
            // competing row, and the violation stays the exception it was. lukk's own route holds no
            // such transaction.
            Validator::make([$this->username => $payload[$this->username]], [$this->username => [Rule::unique($this->model, $this->username)]])->validate();

            throw $e;
        }
    }
}
