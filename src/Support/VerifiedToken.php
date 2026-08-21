<?php

declare(strict_types=1);

namespace Lukk\Support;

use Illuminate\Http\Request;
use Lukk\Lukk;

/**
 * The access token that authenticated the current request, after verification.
 *
 * Lives on the **request**, not on the user model. Sanctum's equivalent (`withAccessToken`) is
 * model state, and that has two failure modes this avoids:
 *
 *  - a model the guard never touched — `$order->user`, a fresh `User::find()` — reports no
 *    abilities, so `tokenCan()` silently denies something the token was actually granted;
 *  - a model that outlives the request it was populated in reports the OLD token's abilities.
 *    Anything holding a user across requests (a memoized guard, a long-lived container binding)
 *    turns that into an authorization decision made from a stale grant.
 *
 * Keyed by guard, because a multi-guard install can authenticate more than one in a request.
 */
class VerifiedToken
{
    /** Request attribute holding `array<string, self>`, keyed by guard name. */
    public const ATTRIBUTE = 'lukk.tokens';

    public function __construct(
        public readonly string $guard,
        public readonly int|string $userId,
        /** The resolved user's class — an id alone is ambiguous when two guards use different providers. */
        public readonly string $userClass,
        public readonly string $familyId,
        public readonly Abilities $abilities,
        /** The verified claims, so downstream code needn't verify the token a second time. */
        public readonly object $claims,
    ) {}

    public static function put(Request $request, self $token): void
    {
        $tokens = $request->attributes->get(self::ATTRIBUTE);
        $tokens = is_array($tokens) ? $tokens : [];
        $tokens[$token->guard] = $token;

        $request->attributes->set(self::ATTRIBUTE, $tokens);
    }

    /**
     * The token for a guard, or — with no guard named — the one for the guard active on this
     * request, falling back to whichever single token is present.
     */
    public static function current(Request $request, ?string $guard = null): ?self
    {
        $tokens = self::all($request);

        if ($tokens === []) {
            return null;
        }

        if ($guard !== null) {
            return $tokens[$guard] ?? null;
        }

        return $tokens[Lukk::currentGuard()] ?? (count($tokens) === 1 ? reset($tokens) : null);
    }

    /**
     * Register a token for the rest of this request cycle without a real bearer token — what
     * `Lukk::actingAs` needs, since setting the user straight onto a guard skips the code that
     * would normally record one.
     *
     * Bound **scoped**, not static: a scoped binding is torn down between requests (Octane calls
     * `forgetScopedInstances`), so an application that reaches for this outside a test — an
     * impersonation feature being the obvious temptation — cannot leave a token behind that
     * authorizes the next visitor to hit the same worker.
     */
    public static function assume(self $token): void
    {
        app()->scoped(self::class, fn () => $token);
    }

    /**
     * @return array<string, self>
     */
    private static function all(Request $request): array
    {
        $tokens = $request->attributes->get(self::ATTRIBUTE);
        $tokens = is_array($tokens) ? $tokens : [];

        // A real, verified bearer token always wins: an assumed one is only consulted when the
        // guard recorded nothing at all.
        if ($tokens === [] && app()->bound(self::class)) {
            $assumed = app(self::class);
            $tokens = [$assumed->guard => $assumed];
        }

        return $tokens;
    }

    /**
     * The token that authenticated this specific user, if any.
     *
     * Identity is matched on class **and** id: a bare id would let a `Customer` #7 read an `Admin`
     * #7's grant in an install where two guards have different providers.
     */
    public static function forUser(Request $request, object $user): ?self
    {
        foreach (self::all($request) as $token) {
            if ($user::class === $token->userClass && (string) $user->getAuthIdentifier() === (string) $token->userId) {
                return $token;
            }
        }

        return null;
    }
}
