<?php

declare(strict_types=1);

namespace Lukk\Contracts;

interface TokenVerifier
{
    /**
     * Return the validated claims object, or null on any failure.
     */
    public function verify(string $jwt): ?object;
}
