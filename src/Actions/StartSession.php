<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Support\Str;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Contracts\TokenIssuer;
use Lukk\Lukk;
use Lukk\Support\Abilities;
use Lukk\Support\TokenContext;
use Lukk\Support\TokenPair;
use RuntimeException;

/**
 * Begin a session at login: a new family + first refresh token + access token.
 */
class StartSession
{
    /**
     * @param  array{refresh_ttl:int,...}  $config
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
        $expiresAt = now()->getTimestamp() + $this->config['refresh_ttl'];
        $granted = $abilities === null ? null : Abilities::fromArray($abilities);

        // `''`, not null, for a grant that is pinned to NOTHING — a capped impersonation session, a
        // zero-scope token. `toScope()` collapses an empty grant to null, and null on the column
        // means "derive from abilitiesUsing", so persisting it directly made the most restricted
        // token there is silently widen to the subject's FULL grant on its first refresh.
        // Resolved before the insert, like the rotate path: evaluating them as arguments to
        // `accessToken()` ran consumer code AFTER the row existed, so a throwing permission store
        // left a live refresh-token row whose secret was never delivered to anyone.
        $context = new TokenContext($this->guard, $userId, $familyId, pinned: $granted !== null);
        $claims = array_merge(Lukk::customClaimsFor($userId), $claims);
        $abilities = $granted ?? Lukk::abilitiesFor($userId, $context);

        $this->repository->persist(
            $userId,
            $familyId,
            null,
            $this->issuer->hash($secret),
            $expiresAt,
            $granted === null ? null : ($granted->toScope() ?? ''),
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

        return new TokenPair($access['token'], $secret, $access['expires_in']);
    }
}
