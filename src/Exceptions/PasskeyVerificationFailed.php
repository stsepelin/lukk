<?php

declare(strict_types=1);

namespace Lukk\Exceptions;

use RuntimeException;

/**
 * A passkey attestation/assertion failed verification (bad signature, wrong
 * origin/RP-ID, malformed client data, …). Distinct from infrastructure errors
 * (a missing library, a decrypt failure) — those must propagate, not be reported
 * to the client as a routine "could not verify".
 */
class PasskeyVerificationFailed extends RuntimeException {}
