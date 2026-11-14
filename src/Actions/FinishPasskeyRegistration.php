<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Validation\ValidationException;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Events\PasskeyRegistered;
use Lukk\Exceptions\PasskeyVerificationFailed;
use Lukk\Passkeys\PasskeyChallengeStore;
use Lukk\Support\NewPasskey;

/**
 * Verify a registration attestation against the pending challenge and persist
 * the new credential.
 */
class FinishPasskeyRegistration
{
    public function __construct(
        private readonly PasskeyChallengeStore $challenges,
        private readonly WebAuthnCeremony $ceremony,
        private readonly PasskeyRepository $passkeys,
    ) {}

    /**
     * @param  array<string,mixed>  $response
     */
    public function __invoke(Authenticatable $user, array $response, ?string $name = null): void
    {
        $challenge = $this->challenges->pullForUser($user->getAuthIdentifier());

        if ($challenge === null) {
            $this->fail();
        }

        try {
            $passkey = $this->ceremony->verifyRegistration($user->getAuthIdentifier(), $response, $challenge);
        } catch (PasskeyVerificationFailed) {
            $this->fail();
        }

        // `credential_id` is the primary key — varchar(255) — but WebAuthn L3 permits a 1023-byte
        // raw id, which is 1364 base64url characters. An authenticator emitting one would be a
        // QueryException (MySQL strict) or, worse, a silent truncation that no later assertion can
        // ever match — a self-inflicted lockout out of the credential just registered. Refuse it as
        // a clean validation failure instead, the same shape as the duplicate check below.
        if (strlen($passkey->credentialId) > 255) {
            $this->fail();
        }

        // `credential_id` is globally unique (the PK) but `findByCredentialId` is guard-SCOPED,
        // because that lookup is the assertion path and must not resolve another guard's credential.
        // So the pre-check has to ask a different question from the one the constraint enforces: a
        // duplicate held by another guard passed this check and then hit the raw DB error the check
        // exists to convert — a 500 instead of a 422, and an existence oracle across the isolation
        // boundary (422 = my guard, 500 = someone else's). Both answers are now the same 422.
        //
        // Reachable rather than theoretical: lukk supports only `none` attestation, so the id in
        // authData is client-chosen.
        if ($this->passkeys->existsByCredentialId($passkey->credentialId)) {
            $this->fail();
        }

        // `transports` is what the CLIENT says about its authenticator, unsigned under `none` attestation,
        // and it went to the database as it arrived: a megabyte of them, or nested arrays, stored on every
        // enrolment. Kept: short tokens of the shape the registry uses (`usb`, `nfc`, `ble`, `hybrid`,
        // `internal`, `smart-card`), a handful at most. They are hints for a later ceremony, never trusted.
        $passkey = new NewPasskey($passkey->credentialId, $passkey->publicKey, $passkey->signCount, self::transports($passkey->transports), $passkey->aaguid);

        $this->passkeys->store($user->getAuthIdentifier(), $passkey, $name);

        event(new PasskeyRegistered($user, $passkey->credentialId, $name));
    }

    /**
     * @param  array<mixed>  $transports
     * @return list<string>
     */
    private static function transports(array $transports): array
    {
        $tokens = array_filter($transports, fn (mixed $transport) => is_string($transport) && preg_match('/\A[a-z][a-z0-9-]{0,31}\z/', $transport) === 1);

        // A list, whatever the client sent: `array_slice` renumbers integer keys only, and `transports`
        // posted as a JSON object arrives with string ones.
        return array_values(array_slice(array_unique($tokens), 0, 8));
    }

    private function fail(): never
    {
        throw ValidationException::withMessages(['credential' => [__('The passkey could not be registered.')]]);
    }
}
