<?php

declare(strict_types=1);

namespace Lukk\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Lukk\Lukk;
use RuntimeException;

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
     * **Test environment only, and it throws elsewhere.** A container `scoped` binding is *not* the
     * safety net it looks like: `forgetScopedInstances()` drops the resolved instance but leaves the
     * BINDING registered, and the binding is a closure that captured this token by value — so on a
     * long-lived worker (Octane, RoadRunner) the very next request re-resolves the same token.
     * Anything reaching for this outside a test, an impersonation feature being the obvious
     * temptation, would hand a leftover grant to the next visitor on that worker. There is no
     * teardown hook that reliably prevents it, so the mechanism refuses to exist in production
     * rather than pretending to be safe there.
     *
     * A real bearer token always wins regardless — see {@see all()} — so this can only ever fill a
     * gap, never override.
     */
    public static function assume(self $token): void
    {
        $app = app();

        if (! method_exists($app, 'runningUnitTests') || ! $app->runningUnitTests()) {
            throw new RuntimeException(
                'Lukk::actingAs() with an explicit ability list is a TEST helper and refuses to run '
                .'outside the test environment: the assumed token would outlive the request on a '
                .'long-lived worker and authorize the next visitor. To grant abilities in '
                .'production, mint a token that carries them — pass them to StartSession, or return '
                .'them from Lukk::abilitiesUsing().',
            );
        }

        // Keyed by guard, exactly as `put()` is. A single slot meant a multi-guard test acting as an
        // admin and then as a user silently clobbered the first — `$admin->tokenCan('admin.all')`
        // came back false with no error to explain it.
        /** @var array<string, self> $assumed */
        $assumed = $app->bound(self::class) ? $app->make(self::class) : [];
        $assumed[$token->guard] = $token;

        $app->scoped(self::class, fn () => $assumed);
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
            /** @var array<string, self> $tokens */
            $tokens = app(self::class);
        }

        return $tokens;
    }

    /**
     * The token that authenticated this specific user, if any.
     *
     * Identity is matched on class **and** id: a bare id would let a `Customer` #7 read an `Admin`
     * #7's grant in an install where two guards have different providers. Where two guards share a
     * provider — same class, same id — class+id no longer separates them, so the active guard
     * breaks the tie, and an ambiguous tie grants nothing. Handing back *some* other guard's grant
     * would answer an authorization question with a token issued for a different audience.
     */
    public static function forUser(Request $request, Authenticatable $user): ?self
    {
        $candidates = [];

        foreach (self::all($request) as $token) {
            /** @var self $token */
            if ($user::class !== $token->userClass || (string) $user->getAuthIdentifier() !== (string) $token->userId) {
                continue;
            }

            if ($token->guard === Lukk::currentGuard()) {
                return $token;
            }

            $candidates[] = $token;
        }

        // One candidate is unambiguous — the ordinary single-guard request, where the active guard
        // may not even be named. Two or more and there is no way to tell which grant applies, so
        // deny by default rather than guess.
        return count($candidates) === 1 ? $candidates[0] : null;
    }
}
