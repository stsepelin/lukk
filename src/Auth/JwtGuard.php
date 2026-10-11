<?php

declare(strict_types=1);

namespace Lukk\Auth;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Lukk\Actions\ClaimSession;
use Lukk\Contracts\TokenVerifier;
use Lukk\Lukk;
use Lukk\Support\Abilities;
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

        if (! $this->couldBeAKey($claims->sub)) {
            return null;
        }

        $user = $this->retrieve($claims->sub);

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
     * Whether `sub` could be the primary key of this guard's user model at all.
     *
     * lukk mints `sub` from a real key, but a co-issuer sharing the secret (the verify-only topology) can
     * put anything there, and PostgreSQL types the lookup's parameter against the column: `"admin"` or a
     * value past bigint against an integer key is SQLSTATE 22P02/22003 — a 500 on every authenticated
     * route for that token, where a `sub` naming no user is a 401. Refused before the query instead.
     * Only for an Eloquent provider whose model looks the subject up by an auto-incrementing integer
     * primary key — the one shape whose column type lukk can know. `retrieveById()` queries
     * `getAuthIdentifierName()`, not the primary key, so an integer key says nothing when the identifier
     * is another column (a public UUID); and `$keyType` defaults to `'int'`, so on a model that only
     * switched `$incrementing` off it is a leftover rather than a statement about a string column.
     * Anything else is the provider's to answer.
     */
    private function couldBeAKey(mixed $sub): bool
    {
        if (! $this->users instanceof EloquentUserProvider) {
            return true;
        }

        $model = $this->users->createModel();

        if ($model->getAuthIdentifierName() !== $model->getKeyName()
            || ! $model->getIncrementing()
            || ! in_array($model->getKeyType(), ['int', 'integer'], true)) {
            return true;
        }

        // An int already is one; a string must be a canonical integer within PHP's (= bigint's) range.
        return is_int($sub) || (is_string($sub) && is_int(filter_var($sub, FILTER_VALIDATE_INT)));
    }

    /**
     * The provider's lookup, with a subject the column's TYPE refuses read as no user.
     *
     * `couldBeAKey()` settles the one shape lukk can be sure of without a query; it cannot see every
     * integer column — a non-incrementing Snowflake key that kept `$keyType = 'int'`, an auth identifier
     * that is another integer column, a 32-bit `increments('id')` handed a subject past int4. PostgreSQL
     * refuses such a parameter with 22P02 (not a number) or 22003 (out of range), which surfaced as a 500;
     * it is a subject naming no user, so a 401. MySQL and SQLite coerce instead and simply match nothing.
     *
     * On PostgreSQL a failed statement aborts the transaction around it, and its COMMIT then silently
     * rolls back. Inside an application's transaction the Eloquent lookup therefore runs in a nested
     * one — a savepoint on the model's connection — so the refusal undoes only itself.
     */
    private function retrieve(mixed $sub): ?Authenticatable
    {
        $model = $this->users instanceof EloquentUserProvider ? $this->users->createModel() : null;
        $connection = $model?->getConnection();
        $savepoint = $connection !== null && $connection->transactionLevel() > 0 ? $connection : null;
        $savepointed = $savepoint?->getName();

        try {
            return $savepoint !== null
                ? $savepoint->transaction(fn () => $this->users->retrieveById($sub))
                : $this->users->retrieveById($sub);
        } catch (QueryException $e) {
            if (! self::refusedTheSubject($e, $sub, $model, $savepointed)) {
                throw $e;
            }

            return null;
        }
    }

    /**
     * Whether a failed lookup is the subject's own type refusal, and swallowing it leaves nothing aborted.
     *
     * - SQLSTATE 22P02 or 22003.
     * - The failing statement is the lookup OF THE SUBJECT: the subject is among its bindings and, for an
     *   Eloquent provider, it reads the model's table. A refusal in another statement — an eager-loaded
     *   `$with` relation with a mistyped key, a global scope, a `retrieved` listener — fails for every user,
     *   and read as "no user" it was a 401 for everybody: an outage nobody was told about. Rethrown.
     * - It ran in the lookup's own savepoint, or on a connection holding no transaction. A provider that
     *   looks up on a connection other than its model's is not covered by that savepoint; inside that
     *   connection's own transaction its refusal is rethrown, never left behind a 401.
     *
     * (A method of its own also because PHPStan sees only the savepointed branch as able to throw.)
     */
    private static function refusedTheSubject(QueryException $e, mixed $sub, ?Model $model, ?string $savepointed): bool
    {
        if (! in_array($e->errorInfo[0] ?? null, ['22P02', '22003'], true) || ! is_scalar($sub)) {
            return false;
        }

        $bound = array_map(fn (mixed $value): ?string => is_scalar($value) ? (string) $value : null, $e->getBindings());

        if (! in_array((string) $sub, $bound, true)) {
            return false;
        }

        // `from users`, `from "users"`, `from `users``, `from "public"."users"` — the table itself (with the
        // connection's prefix), not one whose name merely contains it.
        if ($model !== null) {
            $table = preg_quote($model->getConnection()->getTablePrefix().$model->getTable(), '/');

            if (preg_match('/\bfrom\s+(?:[`"\[]?\w+[`"\]]?\.)?[`"\[]?'.$table.'[`"\]]?(?=\s|$)/i', $e->getSql()) !== 1) {
                return false;
            }
        }

        return $e->getConnectionName() === $savepointed
            || DB::connection($e->getConnectionName())->transactionLevel() === 0;
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
