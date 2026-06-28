<?php

declare(strict_types=1);

namespace Lukk\Contracts;

interface Denylist
{
    public function revokeJti(string $jti, int $ttlSeconds): void;

    public function revokeFamily(string $familyId, int $ttlSeconds): void;

    public function has(string $type, string $id): bool;

    /**
     * True if any of the given `type => id` pairs is denylisted — one round-trip
     * (the guard checks jti + fid on every request).
     *
     * @param  array<string,string>  $types
     */
    public function hasAny(array $types): bool;
}
