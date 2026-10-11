<?php

declare(strict_types=1);

namespace Lukk\Auth;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Lukk\Actions\ClaimSession;
use Lukk\Contracts\TokenVerifier;
use Lukk\Lukk;
use Lukk\Support\Abilities;
use Lukk\Support\SubjectColumn;
use Lukk\Support\VerifiedToken;

/**
 * Request guard (Sanctum Guard analog): pulls the bearer token, verifies it
 * (signature + claims + denylist), and resolves the user. Wired via
 * Auth::extend('lukk-jwt', ...) inside a RequestGuard.
 */
class JwtGuard
{
    public function __construct(
        private readonly TokenVerifier $verifier,
        private readonly UserProvider $users,
        private readonly string $guard = 'api',
        /** This guard's `claim_seconds`, resolved once when the guard is built; 0 = feature off. */
        private readonly int $claimWindow = 0,
    ) {}

    public function __invoke(Request $request): ?Authenticatable
    {
        $token = $request->bearerToken();

        // (An empty bearer fails verification too; the test only skips the work.)
        if ($token === null || $token === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
            return null;
        }

        $claims = $this->verifier->verify($token);

        if ($claims === null) {
            return null;
        }

        // Unclaimed sessions. An integer compare when the feature is off — the action, its cache
        // store and the cache itself are never touched. When on, one cache read per request, before
        // the user lookup, so a session revoked here costs no query.
        // `> 1` would read the same: `UnclaimedSessions::window()` clamps an enabled window to at
        // least 60 seconds, so 1 is not a value this can hold.
        if ($this->claimWindow > 0 && ! $this->claimed((string) ($claims->fid ?? ''), is_numeric($claims->iat ?? null) ? (int) $claims->iat : null)) { // @pest-mutate-ignore: IncrementInteger
            return null;
        }

        if (! $this->couldName($claims->sub)) {
            return null;
        }

        $user = $this->users->retrieveById($claims->sub);

        if ($user === null) {
            return null;
        }

        // Record the VERIFIED token on the request. Everything downstream — the ability middleware,
        // `$user->tokenCan()` — reads from here rather than verifying a second time, and abilities
        // belong to the TOKEN, not the user: the same person on two devices may hold tokens granting
        // different things.
        VerifiedToken::put($request, new VerifiedToken(
            guard: $this->guard,
            userId: $claims->sub,
            userClass: $user::class,
            familyId: (string) ($claims->fid ?? ''),
            abilities: Abilities::fromScope($claims->scope ?? null),
            claims: $claims,
        ));

        // Kept for anything already reading it directly.
        $request->attributes->set('lukk.claims', $claims);

        return $user;
    }

    /**
     * Whether `sub` could name a user at all, decided BEFORE the lookup.
     *
     * lukk mints `sub` from a real identifier, but a co-issuer sharing the secret (the verify-only topology)
     * can put anything there.
     *
     * - A NUL is refused for every provider: pdo_pgsql passes a bound string as a C string, so
     *   `alice\0x` looked up `alice`.
     * - For an Eloquent provider, the subject must be a value the identifier COLUMN's type can hold
     *   (`SubjectColumn`, from the schema): otherwise PostgreSQL refuses the parameter with 22P02/22003, a
     *   500 where a subject naming no user is a 401. Deciding it here, rather than reading a failed lookup
     *   afterwards, runs no failing statement — nothing to abort in a caller's transaction — and leaves a
     *   failure the APPLICATION causes (a scope with a mistyped binding, a mistyped `$with` relation) the
     *   reported 500 it is. Interpreting the exception instead was tried four ways, and each one hid an
     *   outage as a 401 or brought the 500 back for some other model shape.
     * - Any other provider gets the subject as before: there is no column lukk could read.
     */
    private function couldName(mixed $sub): bool
    {
        if (is_string($sub) && str_contains($sub, "\0")) {
            return false;
        }

        if (! $this->users instanceof EloquentUserProvider) {
            return true;
        }

        return (is_int($sub) || is_string($sub)) && SubjectColumn::admits($this->users->createModel(), $sub);
    }

    private function claimed(string $familyId, ?int $issuedAt): bool
    {
        // Resolved on THIS guard, so the revocation it may perform hits this guard's repository. The
        // token's `iat` decides whether it is the sign-in's original — an access token carries no
        // lineage, so this half stays the mint-time comparison; with the window clamped past
        // `access_ttl + leeway`, the original access token has normally expired before it could be
        // late, so in practice this path claims and the refresh path is the one that revokes.
        // `ClaimSession` returns a bool; `onGuard()` is typed `mixed`, so the cast states it.
        return (bool) Lukk::onGuard($this->guard, fn () => app(ClaimSession::class)($familyId, $issuedAt)); // @pest-mutate-ignore: RemoveBooleanCast
    }
}
