<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Validation\ValidationException;

/**
 * Re-verify the authenticated user's password for a step-up ("sudo") confirmation.
 */
class ConfirmPassword
{
    public function __construct(private readonly UserProvider $users) {}

    public function __invoke(Authenticatable $user, string $password): void
    {
        if (! $this->users->validateCredentials($user, ['password' => $password])) {
            throw ValidationException::withMessages(['password' => [__('The provided password is incorrect.')]]);
        }
    }
}
