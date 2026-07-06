<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Lukk\Lukk;
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

        return $this->model::create([
            'name' => $payload['name'],
            $this->username => $payload[$this->username],
            'password' => Hash::make((string) $payload['password']),
        ]);
    }
}
