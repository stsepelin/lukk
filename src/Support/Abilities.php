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
                    json_encode($ability),
                ));
            }

            $granted[] = $ability;
        }

        return new self(array_values(array_unique($granted)));
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
