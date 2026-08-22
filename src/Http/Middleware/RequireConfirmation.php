<?php

declare(strict_types=1);

namespace Lukk\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\Request;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\Denylist;
use Lukk\Http\Concerns\ResolvesPresentingFamily;
use Lukk\Lukk;
use Symfony\Component\HttpFoundation\Response;

/**
 * Gate a route behind a recent step-up confirmation ("sudo" mode). The client
 * earns a confirmation token (POST /auth/confirm-password, or a passkey assertion)
 * and presents it in the configured header; the token is valid for the whole
 * `confirm.ttl` window. Returns 423 Locked when missing/expired/foreign.
 */
class RequireConfirmation
{
    use ResolvesPresentingFamily;

    public function __construct(
        private readonly AuthManager $auth,
        private readonly Denylist $denylist,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $token = (string) $request->header((string) config('lukk.confirm.header', 'X-Lukk-Confirmation'), '');
        $challenges = $this->challenges();
        $subject = $challenges->verify('reauth', $token);

        abort_if(
            $subject === null || $subject !== (string) $request->user()?->getAuthIdentifier(),
            423,
            'This action requires confirmation.',
        );

        // Bound to the SESSION that earned it, not just the subject.
        //
        // A step-up asserts "the person at this keyboard re-proved themselves just now". Checking
        // the subject alone made the confirmation bearer authority across every token that subject
        // holds: a machine token — one that could never earn a confirmation itself, because the
        // earning routes are ability-gated — could present the one the user's browser earned and act
        // with it. Enabling two-factor, registering a passkey, regenerating recovery codes and
        // erasing the account were all reachable that way.
        //
        // `fid` is stable across rotation, so refreshing mid-window keeps the confirmation valid.
        $boundTo = $challenges->familyOf('reauth', $token);

        // STRICT equality, so `null === null` still admits the co-issuer topology — a token minted
        // by another service sharing the secret legitimately carries no `fid`, and neither does a
        // confirmation earned by it — while an UNBOUND confirmation is refused to a bearer that has
        // one. Accepting that combination was justified as pre-0.6 compatibility, but the issuer has
        // always stamped `fid` on access tokens, so no real pre-0.6 token needs it: the only thing
        // the loose branch bought was a `confirm.ttl`-wide window in which the old bypass still
        // worked. The upgrade cost is one 423 and a re-confirm.
        if ($boundTo !== $this->presentingFamily($request)) {
            // A machine-readable `reason`, because this 423 and the missing/expired one above mean
            // different things to a client: the first is fixed by earning a confirmation, this one
            // is fixed by discarding a confirmation that belongs to another session. Without a key
            // to branch on, a client can only match the English prose, which is a drift surface of
            // its own.
            abort(response()->json([
                'message' => 'This confirmation belongs to a different session.',
                'reason' => 'confirmation_session_mismatch',
            ], 423));
        }

        return $next($request);
    }

    /**
     * The challenge verifier for the guard that ACTUALLY authenticated this request.
     *
     * Resolving `ChallengeToken` from the container would build it from `GuardContext`, which is
     * set by the `lukk.set-guard` middleware — and that only runs inside lukk's own route groups,
     * never on a consumer's `['auth:admin', 'lukk.confirm']` route. The guard would silently fall
     * back to the default, so an admin route verified its step-up against the USERS guard's key
     * and audience: a confirmation earned on the users guard, for an id that collides across the
     * two providers, satisfied the admin gate. Guards are required to hold distinct audiences
     * (`assertGuardsIsolated`), so verifying under the right one is what closes it.
     *
     * Resolved from the auth manager rather than from `GuardContext`, deliberately. `Authenticate`
     * calls `shouldUse()` for the guard that passed, so the manager always names the guard that
     * authenticated THIS request — whereas `GuardContext` is only reset by `lukk.set-guard`, and a
     * long-lived worker (Octane) would carry the previous request's value into a consumer route
     * that never runs it.
     */
    private function challenges(): ChallengeToken
    {
        return new ChallengeToken(Lukk::guardConfig((string) $this->auth->getDefaultDriver()), $this->denylist);
    }
}
