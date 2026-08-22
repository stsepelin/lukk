<?php

declare(strict_types=1);

namespace Lukk\Support;

use InvalidArgumentException;

/**
 * The `scope` claim: what a token is allowed to do.
 *
 * Space-delimited in the token, per RFC 6749 §3.3 and RFC 9068 §2.2.3 — `scope` is the registered
 * claim for this, so a non-lukk verifier or an API gateway can read it without knowing about us.
 * Sanctum calls the same idea "abilities"; the name here follows Sanctum, the wire format follows
 * the RFC.
 *
 * **Deny by default.** A token carrying no `scope` grants nothing: `tokenCan()` is false and the
 * ability middleware refuses. That is deliberate — the alternative (absent means unrestricted)
 * means adding `lukk.ability:admin` to a route while forgetting to configure `abilitiesUsing`
 * silently lets everyone through, and a permission check that fails open is worse than one that
 * fails loudly. Grant `['*']` to opt a token out.
 *
 * Matching is exact, plus two wildcards:
 *   `*`          — everything
 *   `orders.*`   — any ability under the `orders.` prefix
 * A wildcard only ever appears in the GRANT, never in the check: `tokenCan('orders.*')` asks
 * whether the literal ability `orders.*` was granted, so a caller cannot widen their own question.
 */
class Abilities
{
    /**
     * lukk's own ability, for lukk's own session-management routes.
     *
     * Required by `DELETE /auth/sessions*` from a **pinned** token only — one whose grant was passed
     * explicitly to `StartSession`, marked by the `pin` claim. A derived grant is a live human login
     * and is never gated, so it does not need this ability and is not given it. A personal access
     * token pinned to `['ci.deploy']` could otherwise log the account out everywhere; if yours
     * genuinely needs to, pin it alongside: `['ci.deploy', Abilities::SESSIONS]`.
     */
    public const SESSIONS = 'lukk.sessions';

    /**
     * lukk's own ability for account-security operations: the step-up confirmation routes, and
     * changing the password.
     *
     * Step-up is the gateway to everything that can take an account over permanently — enrolling a
     * passkey, disabling two-factor, regenerating recovery codes — and changing the password both
     * revokes every other session and rotates the credential. All of it requires the password, so a
     * pinned token could never do it silently; but "a machine token must not log the account out
     * everywhere" and "a machine token may enrol a permanent authenticator" cannot both be the
     * rule, and this is which one lukk picked.
     */
    public const ACCOUNT = 'lukk.account';

    /**
     * Erasing the account, and exporting everything lukk knows about it.
     *
     * Deliberately NOT covered by {@see ACCOUNT}. That ability already existed and meant "manage my
     * credentials" — step-up, the password, passkeys, two-factor. Folding erasure into it would have
     * handed every already-issued token carrying it the power to irreversibly destroy the account,
     * silently, on upgrade and with no re-consent. It would also invert the privilege ordering: such
     * a token cannot revoke a single other session (that needs `lukk.sessions`) but could delete
     * everything.
     *
     * Note the prefix rule makes this safe: a grant of `lukk.account` does NOT satisfy
     * `lukk.account.delete` — only an exact grant, or `lukk.account.*`, or `*`.
     */
    public const ACCOUNT_DELETE = 'lukk.account.delete';

    /** One ability. Long enough for a namespaced name, short enough that a runaway value is caught. */
    public const MAX_ABILITY_LENGTH = 128;

    /** The assembled `scope` claim, kept well inside proxy header limits. */
    public const MAX_SCOPE_LENGTH = 2048;

    /** @param array<int, string> $granted */
    public function __construct(private readonly array $granted) {}

    /** Parse the space-delimited `scope` claim. Absent/blank grants nothing. */
    public static function fromScope(mixed $scope): self
    {
        return new self(is_string($scope) ? array_values(array_filter(explode(' ', $scope), fn ($s) => $s !== '')) : []);
    }

    /**
     * Build from a granted list, rejecting anything that isn't a legal scope token.
     *
     * RFC 6749 §3.3 defines `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )` — space, `"`, `\` and
     * control characters are excluded, and for a reason that bites here: the claim is
     * space-delimited, so a grant containing a space parses back as TWO abilities. `['orders.read
     * admin']` grants `admin`, which nobody issued. That is a privilege escalation the moment a
     * consumer derives ability names from data — a tenant role, a team name, a DB column — which is
     * the obvious implementation.
     *
     * Throws rather than dropping. A malformed grant is a bug in the calling application, and a
     * silently narrower token would surface later as a confusing 403 somewhere else; a loud failure
     * at the first login in development is cheaper than either. The package already throws at boot
     * for guards sharing an audience, on the same reasoning.
     *
     * Note the message names the offending ability, so it reaches the application log via the
     * default exception handler — the one place in lukk where an ability string does. That is the
     * cost of a diagnosable failure, and it is bounded to the single malformed name (never the
     * granted list); if your names are derived from customer data, it is worth knowing.
     */
    public static function fromArray(array $abilities): self
    {
        $granted = [];

        foreach ($abilities as $ability) {
            if (! is_string($ability) && ! (is_object($ability) && method_exists($ability, '__toString'))) {
                throw new InvalidArgumentException(sprintf(
                    'lukk abilities must be strings; got %s. Check the callback passed to Lukk::abilitiesUsing().',
                    get_debug_type($ability),
                ));
            }

            $ability = (string) $ability;

            if ($ability === '') {
                continue;
            }

            if (preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', $ability) !== 1) {
                throw new InvalidArgumentException(sprintf(
                    'lukk ability %s is not a valid scope token (RFC 6749 §3.3): it may not contain a space, '
                    .'a double quote, a backslash, a control character or a non-ASCII byte. The scope claim is '
                    .'space-delimited, so a space would split one ability into several.',
                    self::describe($ability),
                ));
            }

            // RFC 6749 permits `,` in a scope token, but `lukk.ability:a,b` uses it as the list
            // separator — so an ability named `orders,read` can be MINTED and never REQUIRED: the
            // gate splits it and asks for `orders` OR `read`, silently widening itself. The mint
            // grammar must not be wider than the gate grammar.
            if (str_contains($ability, ',')) {
                throw new InvalidArgumentException(sprintf(
                    'lukk ability %s may not contain a comma: the ability middleware uses it to '
                    .'separate a list (`lukk.ability:a,b`), so such a name could never be required '
                    .'by a route and would widen any gate that tried.',
                    self::describe($ability),
                ));
            }

            if (strlen($ability) > self::MAX_ABILITY_LENGTH) {
                throw new InvalidArgumentException(sprintf(
                    'lukk ability %s is %d bytes, over the %d-byte limit.',
                    self::describe($ability), strlen($ability), self::MAX_ABILITY_LENGTH,
                ));
            }

            $granted[] = $ability;
        }

        $granted = array_values(array_unique($granted));

        // The claim ends up in an `Authorization` header on every request, and the design invites
        // ability names derived from data (a tenant role, a team name, a DB column). Unbounded, that
        // data decides the header size: past ~8 KB nginx/ALB/proxy defaults reject it and EVERY
        // request fails 431/400 — a lockout that only shows up in production. Fail at issue time
        // instead, where the grant is still the developer's to fix.
        if (($length = strlen(implode(' ', $granted))) > self::MAX_SCOPE_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                'lukk granted %d abilities totalling %d bytes, over the %d-byte scope limit. The claim '
                .'rides in an Authorization header, so an oversized grant makes every request fail at '
                .'the proxy. Abilities are meant to be coarse — collapse a family with a wildcard '
                .'(`orders.*`) rather than enumerating it.',
                count($granted), $length, self::MAX_SCOPE_LENGTH,
            ));
        }

        return new self($granted);
    }

    /** Bound what an error message echoes — the offending value reaches the application log. */
    private static function describe(mixed $ability): string
    {
        $encoded = (string) json_encode($ability);

        return strlen($encoded) > 120 ? substr($encoded, 0, 120).'…" (truncated)' : $encoded;
    }

    /** The space-delimited claim value, or null when nothing is granted (so no claim is minted). */
    public function toScope(): ?string
    {
        return $this->granted === [] ? null : implode(' ', $this->granted);
    }

    /** @return array<int, string> */
    public function all(): array
    {
        return $this->granted;
    }

    public function can(string $ability): bool
    {
        if ($ability === '') {
            return false;
        }

        foreach ($this->granted as $grant) {
            if ($grant === '*' || $grant === $ability) {
                return true;
            }

            // `orders.*` covers `orders.read`, but NOT the bare `orders` — a prefix grant is about
            // what lives under the namespace, and treating the namespace itself as included would
            // make `orders.*` and `orders` indistinguishable to anyone reading a policy.
            if (str_ends_with($grant, '.*') && str_starts_with($ability, substr($grant, 0, -1))) {
                return true;
            }
        }

        return false;
    }

    /** @param array<int, string> $abilities */
    public function canAny(array $abilities): bool
    {
        foreach ($abilities as $ability) {
            if ($this->can($ability)) {
                return true;
            }
        }

        return false;
    }

    /** @param array<int, string> $abilities */
    public function canAll(array $abilities): bool
    {
        foreach ($abilities as $ability) {
            if (! $this->can($ability)) {
                return false;
            }
        }

        return $abilities !== [];
    }
}
