<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Support\Str;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Contracts\TokenIssuer;
use Lukk\Lukk;
use Lukk\Support\Abilities;
use Lukk\Support\LongestAccessTtl;
use Lukk\Support\TokenContext;
use Lukk\Support\TokenPair;
use Lukk\Support\UnclaimedSessions;
use RuntimeException;

/**
 * Begin a session at login: a new family + first refresh token + access token.
 */
class StartSession
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private readonly RefreshTokenRepository $repository,
        private readonly TokenIssuer $issuer,
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
        private readonly ?UnclaimedSessions $unclaimed = null,
    ) {}

    /**
     * @param  array<string,mixed>  $claims  Per-login claims for the access token (e.g. `amr`).
     * @param  ?array<int, string>  $abilities  The session's OWN abilities, pinned for its lifetime.
     *                                          Null derives them from `Lukk::abilitiesUsing` on
     *                                          every mint, so a revoked ability takes effect within
     *                                          `access_ttl`. Pass a value when the TOKEN owns the
     *                                          grant rather than the user — a personal access
     *                                          token, or an impersonation session capped below what
     *                                          the target user can do.
     */
    public function __invoke(int|string $userId, array $claims = [], ?array $abilities = null): TokenPair
    {
        $familyId = (string) Str::uuid();
        $secret = $this->issuer->newRefreshSecret();
        $expiresAt = now()->getTimestamp() + (int) ($this->config['refresh_ttl'] ?? 2592000);
        $granted = $abilities === null ? null : Abilities::fromArray($abilities);

        // `''`, not null, for a grant that is pinned to NOTHING — a capped impersonation session, a
        // zero-scope token. `toScope()` collapses an empty grant to null, and null on the column
        // means "derive from abilitiesUsing", so persisting it directly made the most restricted
        // token there is silently widen to the subject's FULL grant on its first refresh.
        // Resolved before the insert, like the rotate path: evaluating them as arguments to
        // `accessToken()` ran consumer code AFTER the row existed, so a throwing permission store
        // left a live refresh-token row whose secret was never delivered to anyone.
        $context = new TokenContext($this->guard, $userId, $familyId, pinned: $granted !== null);

        // `amr` is RESERVED, like `scope` and `pin`: it states how this session was authenticated,
        // and only the caller that performed the authentication can say. Taken from the ARGUMENT
        // only — a `tokenClaimsUsing` hook may neither supply one nor survive one.
        //
        // The argument already won this merge, so lukk's own four sign-in routes were never at risk.
        // The exposed path is `$user->startSession()`, which passes no claims at all: there the
        // hook's `amr` was minted AND persisted as the family's own record, so a hook splatting a
        // user-editable attribute bag into claims let the subject name their own authentication
        // methods — and, now that `amr` is durable, keep them for the family's whole life.
        $authenticationMethods = self::encodeAmr($claims['amr'] ?? null);
        $claims = array_merge(Lukk::customClaimsFor($userId), $claims);
        unset($claims['amr']);

        if ($authenticationMethods !== null) {
            $claims['amr'] = self::decodeAmr($authenticationMethods);
        }

        // `auth_time` (OpenID Connect Core §2): when this session was authenticated. Reserved like `amr`
        // — a hook neither supplies nor survives it — and recomputed on rotation from the family's fixed
        // expiry rather than stored, so it needs no column.
        unset($claims['auth_time']);
        $claims['auth_time'] = now()->getTimestamp();
        $abilities = $granted ?? Lukk::abilitiesFor($userId, $context);

        // Unclaimed until first used (`claim_seconds`). Marked BEFORE the row exists: a cache failure then
        // fails the sign-in cleanly instead of leaving a session nobody can claim. Never for a pinned
        // grant — a personal access token or an impersonation session is delivered by the application,
        // not by a sign-in response that can be lost, and its first use may legitimately be days away.
        if ($this->unclaimed !== null && $granted === null) {
            $this->unclaimed->mark($familyId, (int) ($this->config['refresh_ttl'] ?? 2592000));
        }

        $this->repository->persist(
            $userId,
            $familyId,
            null,
            $this->issuer->hash($secret),
            $expiresAt,
            $granted === null ? null : ($granted->toScope() ?? ''),
            // Persisted so ROTATION can carry it forward: `amr` records how this session was
            // authenticated, and a refresh does not re-authenticate anything. Written only when the
            // sign-in actually supplied one, so nothing lands on a path that has no answer.
            $authenticationMethods,
        );

        // A pinned grant that did not reach storage is the dangerous case, not a harmless one: the
        // token would carry `scope` + `pin` now and re-derive the subject's FULL grant on its first
        // refresh. A custom repository is free to ignore `$scope`; it is not free to let lukk hand
        // back a token whose restriction it silently discarded.
        if ($granted !== null && ! $this->repository->familyIsPinned($familyId)) {
            throw new RuntimeException(
                'lukk could not store this session\'s pinned abilities, so the token would widen to '
                .'the user\'s full grant on its first refresh. Publish the `scope` column '
                .'(`vendor:publish --tag=lukk-migrations`), or make your RefreshTokenRepository '
                .'persist the $scope argument.',
            );
        }

        // The Action resolves the grant; the issuer only stamps it. A pinned grant wins outright —
        // that is what "the TOKEN owns its abilities" means — otherwise it is derived per mint.
        $access = $this->issuer->accessToken($context, $claims, $abilities);
        LongestAccessTtl::record((int) $access['expires_in'], $this->guard, $this->config['denylist_store'] ?? null);

        return new TokenPair($access['token'], $secret, $access['expires_in']);
    }

    /**
     * The longest a single authentication method may be, and the longest the whole claim may be.
     *
     * `amr` is now DURABLE — persisted with the family and re-stamped by every rotation — so an
     * oversized one is no longer a token that dies in an `access_ttl`, it is a family bricked for
     * its whole `refresh_ttl`: every request 431s at the proxy and the only way out is a fresh
     * sign-in. `scope` is bounded for exactly this reason (`Abilities::MAX_ABILITY_LENGTH` /
     * `MAX_SCOPE_LENGTH`); making `amr` durable without bounding it reintroduced the problem in a
     * worse form. RFC 8176's registered values are short ("pwd", "otp", "mfa", "hwk", "swk").
     */
    public const MAX_AMR_METHOD_LENGTH = 64;

    public const MAX_AMR_LENGTH = 256;

    /**
     * `amr` as it goes to storage: a JSON list of short strings, or null when there is nothing
     * worth recording.
     *
     * The claim is lukk's own on every path that mints one (`['pwd']`, `['pwd','otp']`,
     * `['pop','user','mfa']`), but `$claims` is a public parameter and `startSession()` lets an application
     * pass its own — so anything that is not a bounded list of strings is not an `amr`, and storing
     * it would put a shape into the family that every later mint stamps back out.
     */
    public static function encodeAmr(mixed $amr): ?string
    {
        if (! is_array($amr) || $amr === [] || ! array_is_list($amr)) {
            return null;
        }

        foreach ($amr as $method) {
            if (! is_string($method) || $method === '' || strlen($method) > self::MAX_AMR_METHOD_LENGTH) {
                return null;
            }
        }

        $encoded = json_encode($amr);

        return is_string($encoded) && strlen($encoded) <= self::MAX_AMR_LENGTH ? $encoded : null;
    }

    /**
     * The stored `amr` back as a claim value, or null when the column holds anything this would not
     * have written itself.
     *
     * Deliberately the mirror of `encodeAmr` rather than a bare `json_decode`: the write goes
     * through a documented swap seam, so the read cannot assume its own validation ran.
     *
     * @return list<string>|null
     */
    public static function decodeAmr(?string $stored): ?array
    {
        if ($stored === null || strlen($stored) > self::MAX_AMR_LENGTH) {
            return null;
        }

        // A JSON list decodes to a PHP list with or without `assoc`, and `encodeAmr` refuses anything else.
        $decoded = json_decode($stored, true); // @pest-mutate-ignore: TrueToFalse

        return self::encodeAmr($decoded) === null ? null : $decoded;
    }
}
