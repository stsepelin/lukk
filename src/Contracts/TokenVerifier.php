<?php

declare(strict_types=1);

namespace Lukk\Contracts;

interface TokenVerifier
{
    /**
     * Return the validated claims object, or null on any failure.
     */
    /** @return object{sub: mixed, jti: mixed, exp: mixed, fid?: mixed, scope?: mixed, pin?: mixed, iss?: mixed, aud?: mixed}|null */
    public function verify(string $jwt): ?object;
}
