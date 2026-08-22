<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Contracts\TokenIssuer;
use Lukk\Events\RefreshFamilyForked;
use Lukk\Events\RefreshTokenReused;
use Lukk\Exceptions\InvalidRefreshToken;
use Lukk\Lukk;
use Lukk\Support\Abilities;
use Lukk\Support\RefreshTokenRecord;
use Lukk\Support\RotationOutcome;
use Lukk\Support\TokenContext;
use Lukk\Support\TokenPair;
use RuntimeException;

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
        /**
         * Captured when the Action is resolved, alongside the issuer and repository it must agree
         * with — not read from `Lukk::currentGuard()` at invoke time. Consumer code can resolve an
         * Action outside `Lukk::onGuard()` and invoke it inside, and the ambient read then told the
         * abilities callback `admin` while the token was minted with the DEFAULT guard's audience
         * and family row: an admin grant stamped into a customer-audience token, which lukk's own
         * gates then honoured.
         */
        private readonly string $guard = 'api',
    ) {}

    public function __invoke(string $presentedSecret): TokenPair
    {
        $hash = $this->issuer->hash($presentedSecret);
        $grace = $this->config['grace_seconds'];

        // Mint the successor secret + hash before the transaction, so no hashing under the row lock.
        $secret = $this->issuer->newRefreshSecret();
        $secretHash = $this->issuer->hash($secret);

        // Resolve everything the mint needs from application code BEFORE opening the transaction.
        // `abilitiesUsing` and `tokenClaimsUsing` are both consumer callbacks documented as hitting a
        // permission store, and running either under `FOR UPDATE` made lukk's
        // correctness depend on someone else's query: a slow or remote lookup extended the lock on
        // every refresh, taking locks in the opposite order deadlocked against it, and on PostgreSQL
        // a callback that swallowed its own SQL error left the transaction in `25P02` so lukk's
        // commit failed. None of that is reachable now — nothing but lukk's own statements and pure
        // crypto run inside the lock.
        //
        // Safe to read unlocked: a token hash's subject, family and pinned scope are written once at
        // insert and never updated, so the locked read cannot disagree about them. It re-reads
        // everything the DECISION depends on (rotated_at, revoked_at, expires_at) under the lock.
        $preRead = $this->repository->findByHash($hash);
        [$abilities, $claims] = $this->resolveMint($preRead, $grace);

        $outcome = $this->repository->transaction(function () use ($hash, $grace, $secret, $secretHash, $abilities, $claims, $preRead): RotationOutcome {
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

            // The family's own grant, if it has one, survives rotation — otherwise a personal
            // access token would quietly become a user-derived one on its first refresh.
            $this->repository->persist(
                $record->userId,
                $record->familyId,
                $record->id,
                $secretHash,
                $record->expiresAt,
                $record->scope,
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

            // Minted INSIDE the transaction, deliberately — but with the grant already resolved, so
            // this is pure crypto. It used to happen after commit, which meant a throw from
            // `Lukk::abilitiesUsing` left the parent stamped `rotated_at` while the client never
            // received the successor. The client then retried with the token it still held, and past
            // the grace window that is indistinguishable from a replay: reuse detection fired and
            // revoked the whole family. An ordinary permission-store blip logged every device out.
            // CLAUDE.md calls a false-positive family revoke a release blocker, so the mint has to
            // fail where it can still roll the consumption back — and now the callback fails even
            // earlier, before the transaction opens at all.
            //
            // This does NOT weaken the revoke-then-throw invariant: that one is about the FAMILY
            // REVOCATION running after commit, which it still does (see `killFamily` below).
            // The grant was resolved from a read taken before the lock. If that read didn't see
            // THIS row, the grant on hand describes something else — and minting anyway would pass
            // `null`, which the issuer reads as "abilities not in use" and which therefore leaves a
            // decorative `tokenClaimsUsing` scope standing as the signed grant. `token_hash` is
            // unique and both reads use the primary, so this cannot happen; fail closed rather than
            // mint from a guess if it ever does. The transaction rolls back, so nothing is consumed
            // and the client's retry succeeds.
            if ($preRead?->id !== $record->id) {
                throw new RuntimeException(
                    'lukk could not resolve the abilities for this refresh token: the pre-transaction '
                    .'read disagreed with the locked read. Nothing was consumed; retry.'
                );
            }

            $access = $this->issuer->accessToken(
                new TokenContext($this->guard, $record->userId, $record->familyId, pinned: $record->scope !== null),
                $claims,
                $abilities,
            );

            // +1 for the successor being persisted in this transaction.
            return RotationOutcome::issued($record->userId, $record->familyId, $secret, ($siblings ?? 0) + 1, $access);
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
     * The grant the successor will carry: the family's own if it pinned one, otherwise derived.
     *
     * `null` scope means derive; `''` means pinned to nothing. Conflating them would let the most
     * restricted token there is widen to the subject's full grant on its first refresh.
     */
    /**
     * Everything the mint needs from application code, resolved before the transaction opens.
     *
     * Both `abilitiesUsing` and `tokenClaimsUsing` are consumer callbacks that read a permission
     * store, and both used to run under the row lock — abilities directly, claims via the issuer.
     * They share one reject short-circuit so neither can be asked about a token lukk is going to
     * refuse, and so neither can throw early enough to pre-empt reuse detection.
     *
     * @return array{0: ?Abilities, 1: array<string, mixed>}
     */
    private function resolveMint(?RefreshTokenRecord $record, int $grace): array
    {
        $abilities = $this->abilitiesFor($record, $grace);

        return [$abilities, $record === null || $abilities === null && $this->rejectable($record, $grace)
            ? []
            : Lukk::customClaimsFor($record->userId)];
    }

    /** Whether the unlocked read already shows a token the transaction will refuse. */
    private function rejectable(RefreshTokenRecord $record, int $grace): bool
    {
        return $record->revokedAt !== null
            || $record->expiresAt < now()->getTimestamp()
            || ($record->rotatedAt !== null && ($record->rotatedAt + $grace) < now()->getTimestamp());
    }

    private function abilitiesFor(?RefreshTokenRecord $record, int $grace): ?Abilities
    {
        // Anything the transaction is going to REJECT must not reach the application's permission
        // store. Moving the callback ahead of the transaction also moved it ahead of every reject
        // branch, and the reuse case is the one that matters: a replayed token ran the callback
        // first, so a callback that THREW killed the request before `findByHashForUpdate` ever ran
        // — no reuse branch, no family revoke, no `RefreshTokenReused`. Reuse detection was silently
        // off for as long as the permission store misbehaved, and a subject whose derived ability
        // names can be made malformed could turn it off deliberately. Failing open on the theft
        // signal is the one direction this package must never fail.
        //
        // Every field read here is monotone — `revoked_at`, `expires_at`, and `rotated_at` only ever
        // go from null to set — so a row that looks rejectable on the unlocked read is definitively
        // rejectable. The locked re-read still owns the decision.
        if ($record === null || $record->revokedAt !== null || $record->expiresAt < now()->getTimestamp()) {
            return null;
        }

        if ($record->rotatedAt !== null && ($record->rotatedAt + $grace) < now()->getTimestamp()) {
            return null;   // past-grace replay: this is reuse, and the transaction must be the one to say so
        }

        return $record->scope !== null
            ? Abilities::fromScope($record->scope)
            : Lukk::abilitiesFor($record->userId, new TokenContext($this->guard, $record->userId, $record->familyId));
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
        return new TokenPair($outcome->access['token'], $outcome->refreshSecret, $outcome->access['expires_in']);
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
