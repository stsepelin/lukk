<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use WebauthnEmulator\Authenticator;
use WebauthnEmulator\Credential;
use WebauthnEmulator\CredentialInterface;

/**
 * webauthn-emulator builds its COSE key from openssl_pkey_get_details(), which
 * returns the EC x/y coordinates as minimal big-endian integers — leading zero
 * bytes stripped. About 1 in 128 generated keys therefore has a 31-byte x or y,
 * which web-auth/cose-lib rightly rejects (COSE/WebAuthn require fixed 32-byte
 * P-256 coordinates), 500-ing the integration test. It's an upstream bug: the
 * emulator omits the customary left-pad (str_pad($coord, 32, "\0", STR_PAD_LEFT)).
 *
 * To keep the real-crypto round-trip deterministic, this injects a fixed,
 * known-good keypair whose x and y are both full 32 bytes instead of a fresh
 * random one. Real authenticators always emit fixed-length coordinates, so this
 * only substitutes for the test tool — it never touches lukk's own code path.
 */
class FixedKeyAuthenticator extends Authenticator
{
    // A throwaway P-256 private key, verified to have full 32-byte x and y coordinates.
    private const PRIVATE_KEY_PEM = "-----BEGIN PRIVATE KEY-----\n"
        ."MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg28p5Y8W7qhtnIOJ2\n"
        ."2+oSlIdzIkEIhnYED10N3OTykI6hRANCAAS5p8oruDO5UmD9HBJ0tlsX9BIEieyL\n"
        ."LlbL/tFo3KaketEzymDDTPEvkWw8e1el6e3bbZHNNvm4Mj52KOv8nxnM\n"
        ."-----END PRIVATE KEY-----\n";

    protected function createCredential(array $options): CredentialInterface
    {
        $credential = new Credential(
            id: base64_encode(random_bytes(32)),
            privateKey: openssl_pkey_get_private(self::PRIVATE_KEY_PEM),
            rpId: $options['rp']['id'],
            userHandle: $options['user']['id'],
        );

        $this->repository->save($credential);

        return $credential;
    }
}
