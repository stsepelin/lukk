<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Events\TokenAbilityDenied;
use Lukk\Lukk;
use Lukk\Support\Abilities;
use Lukk\Support\VerifiedToken;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Gates one of lukk's own routes on an ability, but **only for a pinned token**.
 *
 * The gap it closes: a token pinned to `['ci.deploy']` — the most restricted thing the API can
 * issue, refused by every ability-gated route in the application — could still call
 * `DELETE /auth/sessions` and log the account out everywhere, or step up and enrol a passkey,
 * because lukk's own routes were gated on authentication alone. That contradicts what pinning a
 * grant is for.
 *
 * **Only a PINNED grant is gated** — one passed explicitly to `StartSession`, marked by the `pin`
 * claim. A derived grant is a live human login and keeps managing its own sessions, so nothing
 * changes for an existing install and no consumer has to discover a new ability name. A personal
 * access token that genuinely needs this asks for `lukk.sessions` in its pin.
 *
 * Not a public alias: this is lukk gating lukk's routes. Applications use `lukk.ability`.
 */
class RequirePinnedAbility
{
    public function __construct(private readonly RefreshTokenRepository $repository) {}

    public function handle(Request $request, Closure $next, string ...$abilities): Response
    {
        // Variadic and validated, like `lukk.ability:a,b` beside it. A single non-variadic parameter
        // made `RequirePinnedAbility::class` with no argument an `ArgumentCountError` — a 500 for
        // ordinary users, not just the denied — and silently dropped everything after the first in
        // `…:a,b`, which is the same syntax meaning ANY-of one line above in the routes file.
        $required = Abilities::fromArray(
            array_values(array_filter(array_map('trim', explode(',', implode(',', $abilities))), fn ($a) => $a !== ''))
        )->all();

        if ($required === []) {
            throw new InvalidArgumentException(
                'RequirePinnedAbility needs at least one ability, e.g. `RequirePinnedAbility::class.\':\'.Abilities::SESSIONS`.',
            );
        }

        // The ACTIVE guard's resolved config: `lukk.set-guard` has already stamped it on both mounts,
        // and reading the global block meant a guard could not switch this on for itself — the flag
        // fails open, so the narrowest token the API can issue kept logging that account out
        // everywhere.
        if (! (Lukk::guardConfig()['features']['gate_auth_routes'] ?? true)) {
            return $next($request);
        }

        $user = $request->user();
        $token = $user === null ? null : VerifiedToken::forUser($request, $user);

        // Only a PINNED grant is gated. A derived one is a live human login — it must keep being
        // able to log its own other devices out, and requiring every consumer to discover a new
        // ability name for that would break working installs on upgrade. A token with no `pin` claim
        // is either derived or predates abilities entirely; both are unchanged.
        if ($token === null || ! $this->isPinned($token)) {
            return $next($request);
        }

        if ($token->abilities->canAny($required)) {
            return $next($request);
        }

        event(new TokenAbilityDenied($token->userId, $token->guard, $token->familyId, $required, false));

        // The same RFC 6750 §3.1 challenge the application gates send, so a client sees one shape.
        throw new HttpException(403, 'This token was issued with a fixed set of abilities, and none of them is '.implode(' or ', $required).'.', headers: [
            'WWW-Authenticate' => sprintf(
                'Bearer error="insufficient_scope", error_description="This token may not perform account-security operations.", scope="%s"',
                implode(' ', $required),
            ),
        ]);
    }

    /**
     * The `pin` claim first, then the database.
     *
     * The claim is stamped by `TokenIssuer` — a documented swap seam — so an implementation that
     * forwards `$abilities` but forgets `TokenContext::$pinned` yields a genuinely pinned token with
     * no claim, and a claim-only check would wave it through. Note the asymmetry that made this
     * worth a round trip: the `scope` half of that same seam fails CLOSED and loudly (every gated
     * route 403s), while this half failed OPEN and silently — the install looks healthy and the
     * control is simply gone.
     *
     * The fallback costs one indexed `exists()`, only when the claim is absent, on routes that
     * already revoke sessions or verify a password.
     */
    private function isPinned(VerifiedToken $token): bool
    {
        if (($token->claims->pin ?? false) === true) {
            return true;
        }

        // A token with no `fid` cannot be checked — and is treated as NOT pinned, deliberately.
        // lukk never mints a pinned token without a family (pinning stores the grant on the family
        // row), so within lukk's own paths no-`fid` implies not-pinned. The case it leaves open is
        // narrow and specific: a CUSTOM `TokenIssuer` that honours `$abilities` while dropping both
        // `TokenContext::$pinned` and the family id. Denying instead would break the supported
        // co-issuer topology — a token minted by another service sharing the secret carries no
        // `fid` — and that is a real deployment, whereas this is a contract violation.
        return $token->familyId !== '' && $this->repository->familyIsPinned($token->familyId);
    }
}
