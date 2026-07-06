<?php

declare(strict_types=1);

namespace Lukk;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Lukk\Models\RefreshToken;

/**
 * Static configuration hub (Sanctum style). Register hooks from your
 * service provider's boot() method.
 */
class Lukk
{
    /** @var (Closure(Request): (Authenticatable|null))|null */
    public static ?Closure $authenticateUsing = null;

    /** @var (Closure(int|string): array<string,mixed>)|null */
    public static ?Closure $tokenClaimsUsing = null;

    /** @var (Closure(array<string,mixed>): Authenticatable)|class-string|null */
    public static Closure|string|null $registerUsing = null;

    /** @var (Closure(Request): array<string,mixed>)|null */
    public static ?Closure $registerValidation = null;

    /** @var class-string|null */
    public static ?string $refreshTokenModel = null;

    public static bool $runsScheduledPruning = true;

    /**
     * Fully customize how login credentials are authenticated.
     */
    public static function authenticateUsing(Closure $callback): void
    {
        self::$authenticateUsing = $callback;
    }

    /**
     * Add custom claims (e.g. roles) to every access token. The callback gets the
     * user id and returns an array of claims; it cannot override standard claims.
     */
    public static function tokenClaimsUsing(Closure $callback): void
    {
        self::$tokenClaimsUsing = $callback;
    }

    /**
     * Fully control how a new user is created at registration (Fortify-style). Given the
     * validated payload (incl. the plaintext `password`), return the new Authenticatable —
     * hash the password yourself. Accepts a closure or an invokable class-string. When unset,
     * lukk creates the configured user model with `name` + the identifier column
     * (config `lukk.username`) + a hashed `password`.
     *
     * @param  (Closure(array<string,mixed>): Authenticatable)|class-string  $callback
     */
    public static function registerUsing(Closure|string $callback): void
    {
        self::$registerUsing = $callback;
    }

    /**
     * Declare your own registration validation rules (username, terms, captcha, …) without
     * subclassing RegisterRequest. The callback receives the request and returns the full
     * rules array, replacing lukk's name + identifier + password defaults.
     *
     * If your rules drop `name` or the identifier column, pair this with a `registerUsing()`
     * hook — the built-in default create still expects those fields and will fail loudly without
     * them (add a captcha/terms field here freely; only the columns the default writes matter).
     *
     * @param  Closure(Request): array<string,mixed>  $callback
     */
    public static function registerValidation(Closure $callback): void
    {
        self::$registerValidation = $callback;
    }

    /**
     * Stop the package from scheduling lukk:prune (call from a provider's
     * boot() if you schedule it yourself).
     */
    public static function disableScheduling(): void
    {
        self::$runsScheduledPruning = false;
    }

    /**
     * Swap the refresh-token Eloquent model (Sanctum-style).
     *
     * @param  class-string  $model
     */
    public static function useRefreshTokenModel(string $model): void
    {
        self::$refreshTokenModel = $model;
    }

    /**
     * @return class-string
     */
    public static function refreshTokenModel(): string
    {
        return self::$refreshTokenModel ?? RefreshToken::class;
    }

    /**
     * Authenticate a user for the duration of the current test (Sanctum-style).
     */
    public static function actingAs(Authenticatable $user, string $guard = 'api'): void
    {
        app('auth')->guard($guard)->setUser($user);
        app('auth')->shouldUse($guard);
    }
}
