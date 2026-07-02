<?php

declare(strict_types=1);

namespace Lukk\Passkeys;

use Cose\Algorithm\Manager as CoseAlgorithmManager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;
use InvalidArgumentException;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Exceptions\PasskeyVerificationFailed;
use Lukk\Support\NewPasskey;
use Lukk\Support\PasskeyRecord;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Default WebAuthnCeremony, wrapping web-auth/webauthn-lib. lukk supplies the
 * challenge and owns storage + the sign-count policy (a no-op counter checker);
 * this only builds ceremony options and verifies attestations/assertions.
 */
class SpomkyWebAuthnCeremony implements WebAuthnCeremony
{
    private readonly SerializerInterface $serializer;

    private readonly AuthenticatorAttestationResponseValidator $attestation;

    private readonly AuthenticatorAssertionResponseValidator $assertion;

    /**
     * @param  array{rp_id:?string,rp_name:string,origins:array<int,string>,user_verification:string}  $config
     */
    public function __construct(private readonly array $config)
    {
        // Fail loud: empty rp_id breaks the RP-ID hash check; empty origins downgrades to domain-suffix matching.
        if (empty($config['rp_id'])) {
            throw new InvalidArgumentException('Passkeys require lukk.passkeys.rp_id — the registrable domain shared by your front-end and API, e.g. "example.com" (set LUKK_PASSKEY_RP_ID).');
        }

        if ($config['origins'] === []) {
            throw new InvalidArgumentException('Passkeys require lukk.passkeys.origins — the allowed front-end origin(s), e.g. "https://app.example.com" (set LUKK_PASSKEY_ORIGINS).');
        }

        $support = new AttestationStatementSupportManager([new NoneAttestationStatementSupport]);
        $this->serializer = (new WebauthnSerializerFactory($support))->create();

        $factory = new CeremonyStepManagerFactory;
        $factory->setCounterChecker(new NullCounterChecker);
        $factory->setAllowedOrigins($this->config['origins']);
        // Pin the COSE signature allow-list to exactly what we advertise in pubKeyCredParams (ES256/RS256)
        // rather than inherit the library's transitive default — so a future lib change can't silently widen it.
        $factory->setAlgorithmManager(CoseAlgorithmManager::create()->add(new ES256, new RS256));

        $this->attestation = AuthenticatorAttestationResponseValidator::create($factory->creationCeremony());
        $this->assertion = AuthenticatorAssertionResponseValidator::create($factory->requestCeremony());
    }

    public function registrationOptions(int|string $userId, string $userName, string $challenge, array $excludeCredentialIds): array
    {
        $options = PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create($this->config['rp_name'], $this->config['rp_id']),
            user: PublicKeyCredentialUserEntity::create($userName, (string) $userId, $userName),
            challenge: $this->decode($challenge),
            pubKeyCredParams: [PublicKeyCredentialParameters::createPk(ES256::ID), PublicKeyCredentialParameters::createPk(RS256::ID)],
            // Login is usernameless (empty allowCredentials → discoverable), so the credential
            // MUST be created as a resident/discoverable key — otherwise a real authenticator
            // stores a non-discoverable credential that passwordless login can never find. UV is
            // requested here (advisory); it's enforced server-side at assertion (see
            // verifyAssertion, which checks the UV flag), the operative gate.
            authenticatorSelection: AuthenticatorSelectionCriteria::create(
                userVerification: $this->config['user_verification'] ?? 'required',
                residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
            excludeCredentials: array_map(fn (string $id) => PublicKeyCredentialDescriptor::create('public-key', $this->decode($id)), $excludeCredentialIds),
        );

        return $this->toArray($options);
    }

    public function verifyRegistration(int|string $userId, array $response, string $challenge): NewPasskey
    {
        try {
            $authenticatorResponse = $this->credentialResponse($response);

            if (! $authenticatorResponse instanceof AuthenticatorAttestationResponse) {
                throw new PasskeyVerificationFailed('Not an attestation response.');
            }

            $options = PublicKeyCredentialCreationOptions::create(
                rp: PublicKeyCredentialRpEntity::create($this->config['rp_name'], $this->config['rp_id']),
                user: PublicKeyCredentialUserEntity::create('', (string) $userId, ''),
                challenge: $this->decode($challenge),
            );

            $record = $this->attestation->check($authenticatorResponse, $options, (string) $this->config['rp_id']);
        } catch (PasskeyVerificationFailed $e) {
            throw $e;
        } catch (Throwable $e) {
            // Any library error on attacker-supplied input (incl. a malformed COSE key) is a verification failure (4xx), not a 500.
            throw new PasskeyVerificationFailed('The passkey registration could not be verified.', previous: $e);
        }

        return new NewPasskey(
            credentialId: $this->encode($record->publicKeyCredentialId),
            publicKey: $this->serializer->serialize($record, 'json'),
            signCount: $record->counter,
            transports: $record->transports,
            aaguid: $record->aaguid->toRfc4122(),
        );
    }

    public function authenticationOptions(string $challenge, array $allowCredentialIds): array
    {
        $options = PublicKeyCredentialRequestOptions::create(
            challenge: $this->decode($challenge),
            rpId: $this->config['rp_id'],
            allowCredentials: array_map(fn (string $id) => PublicKeyCredentialDescriptor::create('public-key', $this->decode($id)), $allowCredentialIds),
            userVerification: $this->config['user_verification'] ?? 'required',
        );

        return $this->toArray($options);
    }

    public function verifyAssertion(array $response, string $challenge, PasskeyRecord $stored): int
    {
        // Decode the stored credential outside the try — a corrupt record is infra failure, not verification failure.
        $source = $this->serializer->deserialize($stored->publicKey, PublicKeyCredentialSource::class, 'json');

        try {
            $authenticatorResponse = $this->credentialResponse($response);

            if (! $authenticatorResponse instanceof AuthenticatorAssertionResponse) {
                throw new PasskeyVerificationFailed('Not an assertion response.');
            }

            $options = PublicKeyCredentialRequestOptions::create(
                challenge: $this->decode($challenge),
                rpId: $this->config['rp_id'],
                userVerification: $this->config['user_verification'] ?? 'required',
            );

            // Usernameless: the user is resolved from our credential_id→userId mapping, so pass null here.
            $record = $this->assertion->check($source, $authenticatorResponse, $options, (string) $this->config['rp_id'], null);
        } catch (PasskeyVerificationFailed $e) {
            throw $e;
        } catch (Throwable $e) {
            // Any library error on attacker-supplied input (incl. a malformed COSE key) is a verification failure (4xx), not a 500.
            throw new PasskeyVerificationFailed('The passkey assertion could not be verified.', previous: $e);
        }

        return $record->counter;
    }

    private function credentialResponse(array $response): mixed
    {
        $credential = $this->serializer->deserialize(json_encode($response), PublicKeyCredential::class, 'json');

        return $credential->response;
    }

    private function toArray(object $options): array
    {
        return json_decode($this->serializer->serialize($options, 'json'), true);
    }

    private function decode(string $value): string
    {
        return base64_decode(strtr($value, '-_', '+/'));
    }

    private function encode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
