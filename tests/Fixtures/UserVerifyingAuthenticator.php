<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use WebauthnEmulator\Authenticator;
use WebauthnEmulator\Credential;

/**
 * The emulator, with a PIN or biometric: it sets the UV bit as well as UP.
 *
 * `pronin/webauthn-emulator` hard-codes UP only (0x01 on assertion, 0x41 on attestation), so with it
 * alone the REAL library never sees a user-verified assertion — and the one rule that lets a passkey
 * skip an enrolled second factor could only ever be tested against the fake ceremony. `$verifies`
 * lets one emulator change its mind between ceremonies: register without UV, then assert with it,
 * which is exactly the stolen-key-with-a-PIN-set-later case WebAuthn L3 §4 forbids relying on.
 */
class UserVerifyingAuthenticator extends Authenticator
{
    public bool $verifies = true;

    /** @param  array<string, mixed>  $extra */
    public function getAssertion(string $rpId, string|array|null $credentialIds, string $challenge, ?string $origin = null, array $extra = []): array
    {
        $credential = $this->getCredential($rpId, $credentialIds);

        $clientDataJson = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $challenge,
            'origin' => $origin ?? 'https://'.$credential->getRpId(),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $clientDataHash = hash('sha256', $clientDataJson, true);

        // UP (0x01), plus UV (0x04) when this authenticator verified the user.
        $authenticatorData = $credential->getRpIdHash().pack('C', $this->verifies ? 0x05 : 0x01).$credential->getPackedSignCount();

        openssl_sign($authenticatorData.$clientDataHash, $signature, $credential->privateKey, OPENSSL_ALGO_SHA256);

        $credential->incrementSignCount();
        $this->repository->save($credential);

        return [
            'id' => static::base64Normal2Url($credential->getId()),
            'rawId' => $credential->getId(),
            'response' => [
                'authenticatorData' => base64_encode($authenticatorData),
                'clientDataJSON' => base64_encode($clientDataJson),
                'signature' => base64_encode($signature),
                'userHandle' => $credential->getUserHandle(),
            ],
            'type' => 'public-key',
        ];
    }

    protected function getAuthData(Credential $credential): string
    {
        // AT (0x40) + UP (0x01), plus UV (0x04) when this authenticator verified the user.
        $authData = parent::getAuthData($credential);

        return substr($authData, 0, 32).pack('C', $this->verifies ? 0x45 : 0x41).substr($authData, 33);
    }
}
