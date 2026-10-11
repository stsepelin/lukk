<?php

declare(strict_types=1);

namespace Lukk\Auth;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Concerns\HasUniqueStringIds;
use Illuminate\Http\Request;
use Lukk\Actions\ClaimSession;
use Lukk\Contracts\TokenVerifier;
use Lukk\Lukk;
use Lukk\Support\Abilities;
use Lukk\Support\VerifiedToken;
use ReflectionMethod;

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
     * Whether `sub` could name a user at all — refused here only where that is certain without any I/O.
     *
     * lukk mints `sub` from a real identifier; a co-issuer sharing the secret (the verify-only topology)
     * mints its own, and must mint one the identifier column can hold.
     *
     * - A NUL is refused for every provider: pdo_pgsql passes a bound string as a C string, so
     *   `alice\0x` looked up `alice`.
     * - For a stock `EloquentUserProvider` (exactly that class) whose auth identifier IS the model's key,
     *   the model itself says what the key holds. With Laravel's `HasUuids`/`HasUlids`/`HasVersion4Uuids`
     *   generating it, a value the model's own `isValidUniqueId()` refuses (for `HasUuids`: anything but the
     *   canonical hyphenated form) — the check Laravel's route-model binding applies, honouring an override.
     *   An incrementing `int` key (the stock `id()`) holds an integer: refused unless canonical and within
     *   signed 64 bits, the widest integer key there is. On PostgreSQL such a subject was SQLSTATE
     *   22P02/22003 on the lookup: a 500 where a subject naming no user is a 401.
     * - Everything else goes to the provider unchecked: a Snowflake key that does not increment, an
     *   identifier that is another column, a 32-bit `increments('id')` handed a value past int4, a domain
     *   type, an `EloquentUserProvider` subclass (it may decode its own identifiers) or a custom provider. A
     *   subject its column cannot hold is then the provider's error, reported as a 500 — the token was
     *   signed by a trusted issuer, so it is that issuer's bug and should surface. Reading the schema to
     *   decide it cost every request a catalog query on the write connection, and interpreting the failed
     *   lookup afterwards hid real outages (a broken scope, a mistyped `$with` relation) as 401s for
     *   everybody.
     */
    private function couldName(mixed $sub): bool
    {
        if (is_string($sub) && str_contains($sub, "\0")) {
            return false;
        }

        // Exactly the stock provider: a subclass may decode its own identifiers before the lookup. (The
        // `instanceof` only tells PHPStan what the class comparison below already guarantees.)
        if (! $this->users instanceof EloquentUserProvider) { // @pest-mutate-ignore: InstanceOfToTrue
            return true; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        if ($this->users::class !== EloquentUserProvider::class) {
            return true;
        }

        $model = $this->users->createModel();

        if ($model->getAuthIdentifierName() !== $model->getKeyName()) {
            return true;
        }

        // The traits generate only the columns `uniqueIds()` names — the key, unless the model says otherwise —
        // and the model's own (protected) `isValidUniqueId()` is what a valid one is, override included.
        if (in_array(HasUniqueStringIds::class, class_uses_recursive($model), true)
            && in_array($model->getKeyName(), $model->uniqueIds(), true)) {
            return (new ReflectionMethod($model, 'isValidUniqueId'))->invoke($model, $sub) === true;
        }

        if (! $model->getIncrementing() || ! in_array($model->getKeyType(), ['int', 'integer'], true)) {
            return true;
        }

        // An int already is one; a string must be a canonical integer (no sign, padding or space) in range.
        return is_int($sub)
            || (is_string($sub) && preg_match('/^(?:0|-?[1-9][0-9]*)\z/', $sub) === 1 && is_int(filter_var($sub, FILTER_VALIDATE_INT)));
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
