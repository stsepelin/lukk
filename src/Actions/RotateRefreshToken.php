<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Contracts\TokenIssuer;
use Lukk\Events\RefreshFamilyForked;
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
 * INVARIANT: the family revocation after a reuse/revoked outcome runs AFTER commit
 * (killFamily/RevokeSession) — revoking inside the transaction then throwing rolls it back.
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
        private readonly Denylist $denylist,
        private readonly array $config,
    ) {}

    public function __invoke(string $presentedSecret): TokenPair
    {
        $hash = $this->issuer->hash($presentedSecret);
        $grace = $this->config['grace_seconds'];

        // Mint the successor secret + hash before the transaction, so no hashing under the row lock.
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

            // First consumption stamps the parent; a within-grace re-consumption keeps it and mints a sibling.
            if ($record->rotatedAt === null) {
                $this->repository->markRotated($record->id);
            } else {
                // A sibling: the grace window absorbed a re-consumption. Normal for a multi-tab or
                // SSR client, and also what a thief racing inside the window gets — after which both
                // chains rotate independently forever, never colliding and never tripping reuse.
                // Counted so a fork is at least VISIBLE; see Events\RefreshFamilyForked.
                $siblings = $this->repository->countLiveTokens($record->familyId);
            }

            $this->repository->persist(
                $record->userId,
                $record->familyId,
                $record->id,
                $secretHash,
                $record->expiresAt,
            );

            // A concurrent family revoke is a set-based UPDATE. Under READ COMMITTED (PostgreSQL)
            // its snapshot can miss the successor just inserted here, leaving a live row behind: the
            // holder keeps rotating, and once the family's denylist entry expires its descendants
            // authenticate again — a logout-all or a reuse kill undoing itself ~15 minutes later.
            //
            // Both revoke paths write the denylist BEFORE the rows, so it is the authoritative early
            // signal. Seeing it here means a revoke is in flight: report `revoked`, which revokes
            // the family again AFTER this commit — when the new row is visible — and rejects.
            if ($this->denylist->has('fid', $record->familyId)) {
                return RotationOutcome::revoked($record->familyId);
            }

            // +1 for the successor being persisted in this transaction.
            return RotationOutcome::issued($record->userId, $record->familyId, $secret, ($siblings ?? 0) + 1);
        });

        if ($outcome->type === 'issued' && $outcome->siblings > $this->forkThreshold()) {
            event(new RefreshFamilyForked($outcome->userId, $outcome->familyId, $outcome->siblings));
        }

        return match ($outcome->type) {
            'issued' => $this->pair($outcome),
            'revoked', 'reuse' => $this->killFamily($outcome->familyId, $outcome->type),
            'expired' => throw new InvalidRefreshToken('expired'),
            default => throw new InvalidRefreshToken('unknown'),
        };
    }

    /**
     * Live tokens a family may hold before the fan-out is worth reporting.
     *
     * A browser opening several tabs at once, or an SSR render racing the client, routinely produces
     * two or three. Reporting those would make the signal useless, so the default only fires above
     * what normal concurrency explains.
     */
    private function forkThreshold(): int
    {
        $configured = $this->config['fork_threshold'] ?? null;

        return is_numeric($configured) ? max(2, (int) $configured) : 3;
    }

    private function pair(RotationOutcome $outcome): TokenPair
    {
        $access = $this->issuer->accessToken($outcome->userId, $outcome->familyId);

        return new TokenPair($access['token'], $outcome->refreshSecret, $access['expires_in']);
    }

    private function killFamily(string $familyId, string $reason): never
    {
        ($this->revokeSession)($familyId);

        // Only genuine REUSE is a theft signal. `revoked` is the ordinary path for a client that
        // retries with a refresh token it still held across a logout — no theft occurred — and apps
        // are told to treat this event as evidence of one. A steady drip of benign events is alert
        // fatigue over the single alarm that matters, so it is no longer dispatched for `revoked`.
        if ($reason === 'reuse') {
            event(new RefreshTokenReused($familyId, $reason));
        }

        throw new InvalidRefreshToken($reason);
    }
}
