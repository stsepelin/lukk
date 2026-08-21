<?php

declare(strict_types=1);

namespace Lukk;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Lukk\Guards\GuardContext;
use Lukk\Models\RefreshToken;
use Lukk\Support\Abilities;
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

    /** @var Closure|null Resolves the abilities a token is minted with. Null = the feature is off. */
    public static ?Closure $abilitiesUsing = null;

    /** @var (Closure(array<string,mixed>): Authenticatable)|class-string|null */
    public static Closure|string|null $registerUsing = null;

    /** @var (Closure(Request): array<string,mixed>)|null */
    public static ?Closure $registerValidation = null;

    /** @var (Closure(Request): string)|null */
    public static ?Closure $rateLimitKeyUsing = null;

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
     * Replace how every lukk throttle identifies a caller.
     *
     * The default is the request IP, with IPv6 collapsed to its /64 (see `rateLimitKey`). Override
     * it to key on something else entirely — a tenant, an API-gateway client id, a CDN's own
     * visitor token — when the source address isn't the right identity for your deployment.
     *
     * The callback runs on every throttled request, so keep it cheap and pure — and note two
     * things. It must return something the caller cannot forge: this value also buckets the login
     * limiter, so a spoofable header would let an attacker mint a fresh bucket per request and walk
     * through the per-origin login limit. And the return is used verbatim as part of a cache key, so
     * namespace anything untrusted. Under a long-running worker (Octane) the closure outlives the
     * request that registered it — derive everything from the `$request` argument, never capture it.
     */
    public static function rateLimitKeyUsing(Closure $callback): void
    {
        self::$rateLimitKeyUsing = $callback;
    }

    /**
     * The bucket every lukk throttle is keyed on.
     *
     * IPv4 is used verbatim. IPv6 is collapsed to its `/64` because that is what a single
     * subscriber is typically handed — keying on the full address would let one visitor mint
     * effectively unlimited buckets and walk straight through every per-IP limit. That only starts
     * to matter once the address is really the visitor's: behind a BFF or reverse proxy it is the
     * proxy until the deployment forwards the real client, so treat this as the second half of
     * setting that up.
     *
     * An IPv4-mapped address (`::ffff:1.2.3.4`) is unwrapped to its IPv4 form first, so it doesn't
     * collapse into a single shared `::/64` bucket with every other mapped address.
     */
    public static function rateLimitKey(Request $request): string
    {
        // `?: 'unknown'` for the same reason the custom key below is guarded: a null `$request->ip()`
        // would normalize to '' and put EVERY caller in one bucket. Applying the rule to the custom
        // key but not to our own fallback was the gap.
        $fallback = self::normalizeIp((string) $request->ip()) ?: 'unknown';

        if (self::$rateLimitKeyUsing !== null) {
            $key = (string) call_user_func(self::$rateLimitKeyUsing, $request);

            // An empty return would silently put EVERY caller in one bucket — the app looks fine
            // until the whole deployment 429s at once. Fall back rather than fail open that way.
            return $key !== '' ? $key : $fallback;
        }

        return $fallback;
    }

    private static function normalizeIp(string $ip): string
    {
        if ($ip === '' || ! str_contains($ip, ':')) {
            return $ip; // IPv4, or nothing to normalize
        }

        $packed = @inet_pton($ip);

        if ($packed === false || strlen($packed) !== 16) {
            return $ip; // not an address we recognise — key on it verbatim rather than guess
        }

        // Prefixes that carry an IPv4 address in their low 32 bits. Truncating these to a /64 would
        // bucket every one of them together — for NAT64 in particular that is a whole IPv6-only
        // client population sharing a single counter, i.e. a self-inflicted 429 storm.
        foreach ([str_repeat("\0", 10)."\xff\xff", "\x00\x64\xff\x9b".str_repeat("\0", 8)] as $embedded) {
            if (str_starts_with($packed, $embedded)) {
                return (string) inet_ntop(substr($packed, 12));
            }
        }

        // A non-numeric value is truthy, so `?:` wouldn't catch it and the cast would yield 0 —
        // clamping that to /1 would put every IPv6 caller in one bucket, the exact global-bucket
        // failure this exists to remove. The floor is 32 for the same reason: a typo like `6` for
        // `64` is otherwise indistinguishable from a deliberate (and catastrophic) setting.
        $configured = config('lukk.rate_limits.ipv6_prefix');
        $prefix = is_numeric($configured) ? (int) $configured : 64;
        $prefix = max(32, min(128, $prefix));
        $whole = intdiv($prefix, 8);
        $bits = $prefix % 8;

        $masked = substr($packed, 0, $whole);

        if ($bits > 0) {
            $masked .= chr(ord($packed[$whole]) & (0xFF << (8 - $bits)) & 0xFF);
        }

        return inet_ntop(str_pad($masked, 16, "\0")).'/'.$prefix;
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
     * Decide what a user's tokens may do — `fn (int|string $userId) => ['orders.read', 'orders.*']`.
     *
     * Takes the id rather than the model, matching `tokenClaimsUsing`, because the issuer mints
     * from an id and resolving a model there would put a query on every refresh.
     *
     * Until this is set, no `scope` claim is minted at all and tokens stay byte-identical to
     * before. Once it is, abilities are **deny by default**: `tokenCan()` and the ability
     * middleware refuse anything not granted. Return `['*']` for an unrestricted token.
     *
     * Re-evaluated on every refresh, not frozen at login — so revoking an ability takes effect
     * within `access_ttl` rather than lasting the life of the refresh token. That is the reason
     * abilities are not stored on the family row.
     */
    public static function abilitiesUsing(Closure $callback): void
    {
        self::$abilitiesUsing = $callback;
    }

    /** The abilities for a user, or null when the feature was never configured. */
    public static function abilitiesFor(int|string $userId): ?Abilities
    {
        return self::$abilitiesUsing === null
            ? null
            : Abilities::fromArray((array) (self::$abilitiesUsing)($userId));
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

        // `guardConfig()` early-returns the top-level config for the default guard's name, so an
        // entry under that name in `lukk.guards` has its overrides silently DROPPED — while still
        // flipping `isMultiGuard()` on, which turns on refresh-token guard scoping (mass logout on
        // existing `guard IS NULL` rows) and mounts a duplicate route group. `guardNames()`
        // de-duplicates, so nothing downstream can notice. Refuse instead.
        if (isset(((array) config('lukk.guards', []))[$default])) {
            throw new RuntimeException("lukk guard [{$default}] is the default guard; configure it in the top level of config/lukk.php, not under 'guards' — an entry there is ignored while still enabling multi-guard mode.");
        }

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
