<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Replace the user's recovery codes with a fresh set; returns the plaintext once.
 */
class RegenerateRecoveryCodes
{
    public function __construct(private readonly int $recoveryCodes) {}

    /**
     * @return array<int,string>
     */
    public function __invoke(Authenticatable $user): array
    {
        return $user->generateRecoveryCodes($this->recoveryCodes);
    }
}
