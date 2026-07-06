<?php

declare(strict_types=1);

namespace Lukk;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Lukk\Guards\GuardContext;
use Lukk\Models\RefreshToken;
use RuntimeException;

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
     * The resolved config for a guard: the top-level `lukk` block for the default guard, or a
     * `guards.{name}` override deep-merged over it. `null` resolves the current guard.
     *
     * @return array<string, mixed>
     */
    public static function guardConfig(?string $name = null): array
    {
        $lukk = (array) config('lukk');
        $name ??= self::currentGuard();

        if ($name === (string) ($lukk['guard'] ?? 'api')) {
            return $lukk;
        }

        $merged = LukkServiceProvider::mergeConfig($lukk, (array) ($lukk['guards'][$name] ?? []));
        unset($merged['guards']);

        return $merged;
    }

    /**
     * Every lukk guard name — the default guard plus any declared under `lukk.guards`.
     *
     * @return array<int, string>
     */
    public static function guardNames(): array
    {
        $lukk = (array) config('lukk');

        return array_values(array_unique([
            (string) ($lukk['guard'] ?? 'api'),
            ...array_keys((array) ($lukk['guards'] ?? [])),
        ]));
    }

    /** Whether more than the default guard is configured (any `lukk.guards` entries). */
    public static function isMultiGuard(): bool
    {
        return ! empty(config('lukk.guards'));
    }

    /** The lukk guard active for the current request (default: `config('lukk.guard')`). */
    public static function currentGuard(): string
    {
        return app(GuardContext::class)->current();
    }

    /** Set the active guard for the current request (used by the per-guard route middleware). */
    public static function useGuard(?string $name): void
    {
        app(GuardContext::class)->use($name);
    }

    /** Run a callback with a specific guard active, restoring the previous one afterwards. */
    public static function onGuard(string $name, Closure $callback): mixed
    {
        return app(GuardContext::class)->on($name, $callback);
    }

    /**
     * Fail fast on an unsafe multi-guard config (called at boot). Every guard must:
     *   - be a `lukk-jwt` guard in config/auth.php (extra guards);
     *   - carry a NON-EMPTY, DISTINCT audience — the token-isolation control, so a token for one
     *     guard is rejected by another regardless of shared keys (RFC 8725 §3.9 / ASVS §9.2.3–9.2.4);
     *   - mount at a distinct host+path, so one guard's routes can't silently shadow another's.
     */
    public static function assertGuardsIsolated(): void
    {
        if (! self::isMultiGuard()) {
            return;
        }

        $default = (string) (config('lukk.guard') ?? 'api');
        $authGuards = (array) config('auth.guards', []);
        $audienceOwners = [];
        $pathMounts = [];

        foreach (self::guardNames() as $name) {
            if ($name !== $default && ($authGuards[$name]['driver'] ?? null) !== 'lukk-jwt') {
                throw new RuntimeException("lukk guard [{$name}] must be declared in config/auth.php with driver 'lukk-jwt'.");
            }

            $cfg = self::guardConfig($name);

            $audiences = array_values(array_filter((array) ($cfg['audience'] ?? [])));
            if ($audiences === []) {
                throw new RuntimeException("lukk guard [{$name}] must declare a non-empty audience — it is what isolates its tokens from other guards.");
            }

            foreach ($audiences as $audience) {
                if (isset($audienceOwners[$audience])) {
                    throw new RuntimeException("lukk guards [{$audienceOwners[$audience]}] and [{$name}] share the audience [{$audience}]; each guard needs a distinct audience so their tokens can't cross.");
                }
                $audienceOwners[$audience] = $name;
            }

            // A null domain is a wildcard (`Route::domain(null)` matches every host), so two guards
            // collide on the same path when they share a domain OR either omits one — the wildcard
            // group (mounted first) would shadow the other's routes.
            $path = (string) ($cfg['path'] ?? 'auth');
            $domain = in_array($cfg['domain'] ?? null, [null, ''], true) ? null : (string) $cfg['domain'];

            foreach ($pathMounts[$path] ?? [] as [$otherName, $otherDomain]) {
                if ($domain === null || $otherDomain === null || $domain === $otherDomain) {
                    throw new RuntimeException("lukk guards [{$otherName}] and [{$name}] can serve the same host and path (a null domain matches every host); give them distinct domains and/or paths.");
                }
            }

            $pathMounts[$path][] = [$name, $domain];
        }
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
