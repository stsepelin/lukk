<?php

declare(strict_types=1);

namespace Lukk\Support;

/**
 * A credential produced by a verified registration ceremony, ready to persist.
 * `publicKey` is the COSE public key (the private key never leaves the device).
 */
class NewPasskey
{
    /**
     * @param  array<int,string>  $transports
     */
    public function __construct(
        public readonly string $credentialId,
        public readonly string $publicKey,
        public readonly int $signCount,
        public readonly array $transports = [],
        public readonly ?string $aaguid = null,
    ) {}
}
