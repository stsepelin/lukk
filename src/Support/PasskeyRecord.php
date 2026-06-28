<?php

declare(strict_types=1);

namespace Lukk\Support;

/**
 * Storage-agnostic snapshot of a stored passkey credential, handed to the
 * assertion ceremony and the management endpoints.
 */
class PasskeyRecord
{
    /**
     * @param  array<int,string>  $transports
     */
    public function __construct(
        public readonly string $credentialId,
        public readonly int|string $userId,
        public readonly string $publicKey,
        public readonly int $signCount,
        public readonly array $transports = [],
        public readonly ?string $aaguid = null,
        public readonly ?string $name = null,
        public readonly ?int $lastUsedAt = null,
    ) {}
}
