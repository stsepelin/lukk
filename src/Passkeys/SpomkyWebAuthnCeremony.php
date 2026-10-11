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
use Lukk\Support\PasskeyAssertion;
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
use Webauthn\CredentialRecord;
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
     * @param  array<string, mixed>  $config
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

        // The manager registers `none` itself as well; listed so the supported set is stated here.
        $support = new AttestationStatementSupportManager([new NoneAttestationStatementSupport]); // @pest-mutate-ignore: RemoveArrayItem
        $this->serializer = (new WebauthnSerializerFactory($support))->create();

        $factory = new CeremonyStepManagerFactory;
        $factory->setCounterChecker(new NullCounterChecker);
        $factory->setAllowedOrigins($this->config['origins']);
        // Pin the COSE signature allow-list to exactly what we advertise in pubKeyCredParams (ES256/RS256)
        // rather than inherit the library's transitive default — so a future lib change can't silently widen it.
        // (Equivalent today — the library's own default is also ES256 + RS256 — which is the point.)
        $factory->setAlgorithmManager(CoseAlgorithmManager::create()->add(new ES256, new RS256)); // @pest-mutate-ignore: RemoveMethodCall

        $this->attestation = AuthenticatorAttestationResponseValidator::create($factory->creationCeremony());
        $this->assertion = AuthenticatorAssertionResponseValidator::create($factory->requestCeremony());
    }

    public function registrationOptions(int|string $userId, string $userName, string $challenge, array $excludeCredentialIds): array
    {
        $options = PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create($this->config['rp_name'], $this->config['rp_id']),
            user: PublicKeyCredentialUserEntity::create($userName, (string) $userId, $userName),
            challenge: $this->decode($challenge),
            pubKeyCredParams: $this->pubKeyCredParams(),
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
            timeout: $this->timeout(),
        );

        return $this->toArray($options);
    }

    /**
     * How long the browser may prompt, in milliseconds: the challenge's own lifetime, when configured.
     *
     * @return positive-int|null
     */
    private function timeout(): ?int
    {
        $timeout = $this->config['timeout'] ?? null;

        return is_int($timeout) && $timeout > 0 ? $timeout : null;
    }

    /**
     * The COSE algorithms lukk advertises AND accepts — the same pair the algorithm manager is pinned to.
     *
     * @return list<PublicKeyCredentialParameters>
     */
    private function pubKeyCredParams(): array
    {
        return [PublicKeyCredentialParameters::createPk(ES256::ID), PublicKeyCredentialParameters::createPk(RS256::ID)];
    }

    public function verifyRegistration(int|string $userId, array $response, string $challenge): NewPasskey
    {
        try {
            $authenticatorResponse = $this->credentialResponse($response);

            if (! $authenticatorResponse instanceof AuthenticatorAttestationResponse) {
                throw new PasskeyVerificationFailed('Not an attestation response.');
            }

            // `authenticatorSelection` is what `CheckUserVerification` reads (WebAuthn L3 §7.1 step 17).
            // Omitted, it defaults to null and the check returns early — so with the default
            // `user_verification: required` a presence-only authenticator ENROLLED successfully and
            // every later assertion was then refused, because `verifyAssertion` does pass the
            // requirement. The visitor ended up holding a listed passkey that could never be used, and
            // could lock themselves out by trusting that listing and pruning their other factors.
            $options = PublicKeyCredentialCreationOptions::create(
                rp: PublicKeyCredentialRpEntity::create($this->config['rp_name'], $this->config['rp_id']),
                // The attestation check never reads the user's names, only the options' challenge, RP
                // and user-verification requirement.
                user: PublicKeyCredentialUserEntity::create('', (string) $userId, ''), // @pest-mutate-ignore: EmptyStringToNotEmpty
                challenge: $this->decode($challenge),
                // WebAuthn L3 §7.1 step 22 checks the key's alg against THESE params. Left empty, the
                // library substitutes its own default — equal to ours today, so no test can tell, but
                // a library change would widen what registration accepts without a line changing here.
                pubKeyCredParams: $this->pubKeyCredParams(),
                authenticatorSelection: AuthenticatorSelectionCriteria::create(
                    // A string from env either way; the cast only states it.
                    userVerification: (string) ($this->config['user_verification'] ?? 'required'), // @pest-mutate-ignore: RemoveStringCast
                ),
            );

            // `rp_id` is a non-empty string (the constructor refuses anything else); the cast states it.
            $record = $this->attestation->check($authenticatorResponse, $options, (string) $this->config['rp_id']); // @pest-mutate-ignore: RemoveStringCast
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

    public function authenticationOptions(string $challenge, array $allowCredentialIds, ?string $userVerification = null): array
    {
        $options = PublicKeyCredentialRequestOptions::create(
            challenge: $this->decode($challenge),
            rpId: $this->config['rp_id'],
            allowCredentials: array_map(fn (string $id) => PublicKeyCredentialDescriptor::create('public-key', $this->decode($id)), $allowCredentialIds),
            userVerification: $this->userVerification($userVerification),
            timeout: $this->timeout(),
        );

        return $this->toArray($options);
    }

    public function isMultiFactor(PasskeyRecord $stored): bool
    {
        try {
            return $this->source($stored)->uvInitialized === true;
        } catch (Throwable) {
            // Unreadable is not "multi-factor": the conservative answer for a question whose TRUE
            // lets a step-up demand more, and whose FALSE never lets anyone skip a factor.
            return false;
        }
    }

    public function verifyAssertion(array $response, string $challenge, PasskeyRecord $stored, ?string $userVerification = null, int|string|null $owner = null): PasskeyAssertion
    {
        // Decode the stored credential outside the try — a corrupt record is infra failure, not verification failure.
        $source = $this->source($stored);

        // Read BEFORE `check()`: the library sets `uvInitialized` from this assertion's UV flag in
        // memory (WebAuthn L3 §7.2, "update credentialRecord with new state values"), and the spec
        // forbids relying on the flag in the very ceremony that would flip it — "including an
        // authentication ceremony where it would be updated to TRUE". lukk persists only the sign
        // count, so that update is skipped, which the same step allows: it "SHOULD require
        // authorization by an additional authentication factor equivalent to WebAuthn user
        // verification; if not authorized, skip this step." A TOTP is possession, not equivalent.
        $wasUvInitialized = $source->uvInitialized === true;

        try {
            $authenticatorResponse = $this->credentialResponse($response);

            if (! $authenticatorResponse instanceof AuthenticatorAssertionResponse) {
                throw new PasskeyVerificationFailed('Not an assertion response.');
            }

            $options = PublicKeyCredentialRequestOptions::create(
                challenge: $this->decode($challenge),
                rpId: $this->config['rp_id'],
                userVerification: $this->userVerification($userVerification),
            );

            // Usernameless: the user is resolved from our credential_id→userId mapping, so pass null here.
            // The owner a step-up already identified (WebAuthn L3 §7.2 step 6), or null at sign-in, where the
            // response must carry the user handle.
            $record = $this->assertion->check($source, $authenticatorResponse, $options, (string) $this->config['rp_id'], $owner === null ? null : (string) $owner); // @pest-mutate-ignore: RemoveStringCast
        } catch (PasskeyVerificationFailed $e) {
            throw $e;
        } catch (Throwable $e) {
            // Any library error on attacker-supplied input (incl. a malformed COSE key) is a verification failure (4xx), not a 500.
            throw new PasskeyVerificationFailed('The passkey assertion could not be verified.', previous: $e);
        }

        $userVerified = $authenticatorResponse->authenticatorData->isUserVerified();

        return new PasskeyAssertion(
            signCount: $record->counter,
            userVerified: $userVerified,
            multiFactor: $userVerified && $wasUvInitialized,
        );
    }

    /**
     * The stored credential, deserialized. Typed as `CredentialRecord` — the parent — because that is
     * what the library's serializer actually returns for this payload; `uvInitialized` and the
     * backup flags live there.
     */
    private function source(PasskeyRecord $stored): CredentialRecord
    {
        return $this->serializer->deserialize($stored->publicKey, PublicKeyCredentialSource::class, 'json');
    }

    /** The requirement for one ceremony: the caller's, or the configured one. */
    private function userVerification(?string $requested): string
    {
        return $requested ?? ($this->config['user_verification'] ?? 'required');
    }

    /** @param  array<string, mixed>  $response */
    private function credentialResponse(array $response): mixed
    {
        $credential = $this->serializer->deserialize(json_encode($response), PublicKeyCredential::class, 'json');

        return $credential->response;
    }

    /** @return array<string, mixed> */
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
