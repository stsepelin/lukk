<?php

declare(strict_types=1);

namespace Lukk\Events;

/**
 * Dispatched when an assertion's signature counter regresses — a signal that the
 * authenticator may have been cloned. A security event; attach a listener to
 * alert (and consider disabling the credential). The credential-layer analog of
 * refresh-token family reuse detection.
 */
class PasskeyCloneDetected
{
    public function __construct(
        public readonly int|string $userId,
        public readonly string $credentialId,
    ) {}
}
