<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Contracts\TokenIssuer;
use Lukk\Events\RefreshTokenReused;
use Lukk\Exceptions\InvalidRefreshToken;
use Lukk\Support\RotationOutcome;
use Lukk\Support\TokenPair;

/**
 * The rotation policy (storage-agnostic). Decision tree, evaluated under a row
 * lock inside the repository transaction:
 *   - unknown               -> reject
 *   - hard-revoked          -> kill family, reject
 *   - expired               -> reject
 *   - consumed, past grace  -> REUSE: kill family, reject
 *   - consumed, in grace    -> tolerate (mint a fresh sibling, no logout)
 *   - fresh                 -> stamp consumed, issue successor
 *
 * INVARIANT: the family revocation that follows a reuse/revoked outcome happens
 * AFTER the transaction commits (in killFamily, via RevokeSession). Revoking
 * inside the transaction and then throwing would roll the revocation back.
 */
class RotateRefreshToken
{
    /**
     * @param  array{grace_seconds:int,...}  $config
     */
    public function __construct(
        private readonly RefreshTokenRepository $repository,
        private readonly TokenIssuer $issuer,
        private readonly RevokeSession $revokeSession,
        private readonly array $config,
    ) {}

    public function __invoke(string $presentedSecret): TokenPair
    {
        $hash = $this->issuer->hash($presentedSecret);
        $grace = $this->config['grace_seconds'];

        // Mint the successor secret + hash BEFORE opening the transaction so no
        // entropy/hashing work happens while the row lock is held.
        $secret = $this->issuer->newRefreshSecret();
        $secretHash = $this->issuer->hash($secret);

        $outcome = $this->repository->transaction(function () use ($hash, $grace, $secret, $secretHash): RotationOutcome {
            $record = $this->repository->findByHashForUpdate($hash);

            if ($record === null) {
                return RotationOutcome::unknown();
            }

            if ($record->revokedAt !== null) {
                return RotationOutcome::revoked($record->familyId);
            }

            if ($record->expiresAt < now()->getTimestamp()) {
                return RotationOutcome::expired();
            }

            $consumedPastGrace = $record->rotatedAt !== null
                && ($record->rotatedAt + $grace) < now()->getTimestamp();

            if ($consumedPastGrace) {
                return RotationOutcome::reuse($record->familyId);
            }

            // First consumption stamps the parent. A within-grace re-consumption
            // keeps the original stamp and mints another sibling — no logout.
            if ($record->rotatedAt === null) {
                $this->repository->markRotated($record->id);
            }

            $this->repository->persist(
                $record->userId,
                $record->familyId,
                $record->id,
                $secretHash,
                $record->expiresAt,
            );

            return RotationOutcome::issued($record->userId, $record->familyId, $secret);
        });

        return match ($outcome->type) {
            'issued' => $this->pair($outcome),
            'revoked', 'reuse' => $this->killFamily($outcome->familyId, $outcome->type),
            'expired' => throw new InvalidRefreshToken('expired'),
            default => throw new InvalidRefreshToken('unknown'),
        };
    }

    private function pair(RotationOutcome $outcome): TokenPair
    {
        $access = $this->issuer->accessToken($outcome->userId, $outcome->familyId);

        return new TokenPair($access['token'], $outcome->refreshSecret, $access['expires_in']);
    }

    private function killFamily(string $familyId, string $reason): never
    {
        ($this->revokeSession)($familyId);

        event(new RefreshTokenReused($familyId, $reason));

        throw new InvalidRefreshToken($reason);
    }
}
