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
use Lukk\Support\LongestAccessTtl;
use Lukk\Support\RefreshTokenRecord;
use Lukk\Support\RotationOutcome;
use Lukk\Support\TokenContext;
use Lukk\Support\TokenPair;
use Lukk\Tokens\Jwt\FirebaseTokenIssuer;
use RuntimeException;
use Throwable;

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
     * @param  array<string, mixed>  $config
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
        /** Null unless this guard's `claim_seconds` is on. */
        private readonly ?ClaimSession $claim = null,
    ) {}

    public function __invoke(#[\SensitiveParameter] string $presentedSecret): TokenPair
    {
        $hash = $this->issuer->hash($presentedSecret);
        $grace = (int) ($this->config['grace_seconds'] ?? 30);

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

        // Unclaimed sessions: a refresh is a use, so it claims — or, after the window, revokes. Here,
        // before the transaction and before any application callback, for the same reasons those are
        // hoisted: a cache round trip must not extend the row lock, and the revocation it may perform
        // must run outside a transaction. Only for a token the transaction would accept; a rejected
        // one is not a use, and reuse detection must stay the thing that decides a replay.
        // `unclaimed`, not `reuse`: nothing was replayed, so `RefreshTokenReused` does not fire.
        if ($this->claim !== null && $preRead !== null && ! $this->rejectable($preRead, $grace)
            // The family's ORIGINAL row is the never-rotated one created with it; a successor row was
            // created by a refresh, so presenting it proves the session was used. `rotatedAt` is asked
            // here rather than in `ClaimSession` because rotation is a use of ANY row, original or not.
            && ! ($this->claim)(
                $preRead->familyId,
                $preRead->rotatedAt === null ? $preRead->createdAt : null,
                $preRead->rotatedAt === null ? $preRead->original : false,
                $preRead->rotatedAt === null && $preRead->original === null && $preRead->createdAt === null,
            )) {
            throw new InvalidRefreshToken('unclaimed');
        }

        [$abilities, $claims] = $this->resolveMint($preRead, $grace);

        $outcome = $this->repository->transaction(function () use ($hash, $grace, $secret, $secretHash, $abilities, $claims, $preRead): RotationOutcome {
            $record = $this->repository->findByHashForUpdate($hash);

            if ($record === null) {
                return RotationOutcome::unknown();
            }

            // The row itself is revoked, so its family's revoke has already run — denylist first,
            // then every row, twice (see DatabaseRefreshTokenRepository::revokeFamily). Running it
            // again here wrote the denylist and two UPDATEs per request, which made one dead token
            // replayed at an unauthenticated route a write amplifier. Only the denylist-only case
            // below, a revoke still in flight, needs a second pass.
            if ($record->revokedAt !== null) {
                return RotationOutcome::dead();
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
                // Carried forward with the grant, and for the same reason: `amr` describes how the
                // SESSION was authenticated, which a refresh does not repeat. Losing it made the
                // claim vanish from the first refreshed token, so a route gated on it stopped
                // working within one access_ttl — fail-closed if the gate was written tightly,
                // fail-OPEN if written as `!isset($amr) || in_array(...)`.
                $record->amr,
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
            //
            // The `?? 0` fallback is reached only where the parent was FRESH — no sibling was minted,
            // so the family holds exactly this one live token. `forkThreshold()` is floored at 2, so
            // no value that branch can produce ever clears it and the number never leaves this line:
            // mutating the fallback is equivalent. Pest ignores per line and per mutator name, not per
            // literal, so this necessarily covers the `+ 1` as well — that one is real, and is pinned
            // by the exact sibling counts asserted in `RotateRefreshTokenTest`.
            return RotationOutcome::issued($record->userId, $record->familyId, $secret, ($siblings ?? 0) + 1, $access, $record->expiresAt); // @pest-mutate-ignore: DecrementInteger,IncrementInteger
        });

        // ADVISORY, so it must not be able to cost the caller its session. Dispatched synchronously
        // between the commit and the return, a throwing listener left the successor committed while the
        // client got an exception — and past the grace window that is indistinguishable from a replay,
        // so reuse detection revoked the whole family. That is the precise hole the mint was moved
        // inside the transaction to close, reopened by an alerting hook returning 500. The listener's
        // failure is reported and the rotation stands.
        if ($outcome->type === 'issued' && $outcome->siblings > $this->forkThreshold()) {
            try {
                event(new RefreshFamilyForked($outcome->userId, $outcome->familyId, $outcome->siblings));
            } catch (Throwable $e) {
                report($e);
            }
        }

        return match ($outcome->type) {
            'issued' => $this->pair($outcome),
            'revoked', 'reuse' => $this->killFamily($outcome->familyId, $outcome->type),
            'dead' => throw new InvalidRefreshToken('revoked'),
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

        if ($record === null || $abilities === null && $this->rejectable($record, $grace)) {
            return [$abilities, []];
        }

        // The signing key too: the mint below signs under the row lock, and an asymmetric key is a file
        // read plus, with a passphrase, a decrypt — neither belongs inside `FOR UPDATE`. After the reject
        // short-circuit, so an unreadable key cannot pre-empt reuse detection; a failure here consumes
        // nothing, and the client's retry is an ordinary one. A rebound issuer owns its own key handling.
        if ($this->issuer instanceof FirebaseTokenIssuer) {
            $this->issuer->warm();
        }

        // `amr` after the consumer's claims, like `scope` and `pin`: it is the family's own record of
        // how this session was authenticated, and a `tokenClaimsUsing` hook may neither forge one nor
        // erase the real one.
        $claims = Lukk::customClaimsFor($record->userId);
        unset($claims['amr'], $claims['auth_time']);

        // When the SESSION was authenticated, which a refresh does not repeat: the family's expiry is fixed
        // at sign-in (`refresh_ttl` from then) and inherited by every successor, so it dates the sign-in
        // without a column. A `refresh_ttl` changed since shifts it by the difference.
        $refreshTtl = $this->config['refresh_ttl'] ?? 2592000;
        // The cast changes nothing for a numeric value, and StartSession reads the same key with the same
        // cast, so a non-numeric one gave the family a zero lifetime and never reaches a live rotation.
        $claims['auth_time'] = $record->expiresAt - (int) $refreshTtl; // @pest-mutate-ignore: RemoveIntegerCast

        // Re-validated on the way OUT, not trusted because it was validated on the way in. The
        // column is written through `RefreshTokenRepository`, a documented swap seam, and
        // `RefreshTokenRecord::$amr` is a plain string — so a replacement repository, or a row
        // edited by hand, can put anything here. `is_array()` alone let a decoded JSON OBJECT
        // through, and RFC 8176 §1 / RFC 7519 §4.1 make `amr` an array of StringOrURI.
        $amr = StartSession::decodeAmr($record->amr);

        if ($amr !== null) {
            $claims['amr'] = $amr;
        }

        return [$abilities, $claims];
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
        // Only ever called on an `issued` outcome, which is the one shape that carries both.
        // `RotationOutcome::issued()` is the only constructor of that type and declares both
        // non-nullable, so neither half can be false for any input: weakening the `&&` or removing the
        // assertion outright is equivalent, and what is load-bearing here is the narrowing it gives
        // the analyser rather than any runtime check.
        assert($outcome->access !== null && $outcome->refreshSecret !== null); // @pest-mutate-ignore: BooleanAndToBooleanOr,RemoveFunctionCall

        // After commit, never under the row lock: see `LongestAccessTtl`. ADVISORY, like the fork event
        // above: the successor is committed and the parent consumed, so a cache error here answering 500
        // sent the client's retry past the grace window, where it reads as a replay and revokes the
        // family. Reported, and the rotation stands.
        try {
            LongestAccessTtl::record((int) $outcome->access['expires_in'], $this->guard, $this->config['denylist_store'] ?? null); // @pest-mutate-ignore: RemoveIntegerCast
        } catch (Throwable $e) {
            report($e);
        }

        return new TokenPair($outcome->access['token'], $outcome->refreshSecret, $outcome->access['expires_in'], $outcome->expiresAt);
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
