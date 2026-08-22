<?php

declare(strict_types=1);

namespace Lukk;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Http\Request;
use Illuminate\Support\Enumerable;
use Lukk\Guards\GuardContext;
use Lukk\Models\RefreshToken;
use Lukk\Support\Abilities;
use Lukk\Support\TokenContext;
use Lukk\Support\VerifiedToken;
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

    /**
     * Resolves the abilities a token is minted with. Null = no callback (see {@see usesAbilities()},
     * which is the question to ask; a pinned-grant install has no callback and still uses abilities).
     *
     * A bare string is accepted as a single ability — NOT a space-delimited list. `'a b'` is
     * rejected by the scope-token charset, because a space would split one ability into two.
     *
     * @var (Closure(int|string, TokenContext): (array<int, string|\Stringable>|Arrayable<int, string>|Enumerable<int, string>|string))|null
     */
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
     * Decide what a user's tokens may do —
     * `fn (int|string $userId, TokenContext $context) => ['orders.read', 'orders.*']`.
     *
     * Takes the id rather than the model, matching `tokenClaimsUsing`, because the issuer mints
     * from an id and resolving a model there would put a query on every refresh. The
     * {@see TokenContext} carries what else is known about the mint — the guard, the session's
     * family id — so a multi-guard install can grant an `admin` token something a `customer` token
     * never gets, from the same user row.
     *
     * Until this is set, no `scope` claim is minted at all and tokens stay byte-identical to
     * before. Once it is, abilities are **deny by default**: `tokenCan()` and the ability
     * middleware refuse anything not granted. Return `['*']` for an unrestricted token.
     *
     * **Name abilities after resources, never after facts about the person.** An ability name is a
     * public identifier: it travels in the `scope` claim of every access token (so every proxy, API
     * gateway and APM on the path sees it), it is published on the user resource, and it appears as
     * a literal string in your JavaScript bundle — which anyone can download. `hiv_clinic.records.
     * read` is a special-category disclosure at each of those hops; `clinic_a.records.read` is not.
     * The charset validation below polices the SYNTAX of a name and can say nothing about its
     * meaning; that part is yours.
     *
     * Runs **outside** lukk's refresh transaction, resolved before it opens — so a slow permission
     * lookup doesn't extend a row lock, a callback taking locks in the opposite order can't deadlock
     * against lukk, and an error it swallows can't poison lukk's transaction. It may still throw:
     * that fails the refresh cleanly, before the presented token has been consumed.
     *
     * Re-evaluated on every mint, not frozen at login — so revoking an ability takes effect within
     * `access_ttl` rather than lasting the life of the refresh token. A session that must instead
     * carry a FIXED grant (a personal access token, an impersonation session capped below the
     * target user) passes its abilities to `StartSession`, which stores them on the family row and
     * replays them through every rotation; this callback is not consulted for those.
     */
    public static function abilitiesUsing(Closure $callback): void
    {
        self::$abilitiesUsing = $callback;
    }

    /**
     * Whether this install uses abilities at all.
     *
     * Deliberately NOT "is `$abilitiesUsing` set". An install whose grants come only from an
     * explicit `StartSession` pin has no callback and uses abilities very much indeed — and asking
     * the narrower question made a token pinned to ZERO abilities indistinguishable from a server
     * that doesn't use the feature, so the client rendered the full privileged UI for the most
     * restricted token the API can issue.
     */
    public static function usesAbilities(?string $guard = null): bool
    {
        // Read through the ACTIVE GUARD's resolved config, not the global block. `guardConfig()`
        // deep-merges `lukk.guards.{name}` over the top level, so a deployment that switched the
        // feature on for its admin guard alone had that setting silently dropped — and the flag
        // fails OPEN, so the claims hook became the authorization layer on that guard.
        return self::$abilitiesUsing !== null || (bool) (self::guardConfig($guard)['features']['abilities'] ?? false);
    }

    /**
     * The custom claims for a user, or `[]` when no hook is configured.
     *
     * Resolved by the calling ACTION, never by the issuer — the same rule abilities follow, and for
     * the same two reasons: policy does not belong inside a swap seam, and this is application code
     * that must not run while lukk holds a row lock.
     *
     * @return array<string, mixed>
     */
    public static function customClaimsFor(int|string $userId): array
    {
        $claims = self::$tokenClaimsUsing !== null ? (self::$tokenClaimsUsing)($userId) : [];

        return is_array($claims) ? $claims : [];
    }

    /** The abilities for a user, or null when no callback is configured. */
    public static function abilitiesFor(int|string $userId, TokenContext $context): ?Abilities
    {
        if (self::$abilitiesUsing === null) {
            // The layer can be ON without a callback — the pinned-grant-only install the
            // `features.abilities` flag exists for. There, "this token derives nothing" is an EMPTY
            // grant, not "abilities aren't in use": returning null left the issuer's reservation
            // switched off, so a `scope` from `tokenClaimsUsing` was signed and honoured by the
            // gates. The claims hook would have become the authorization layer.
            // The CONTEXT's guard, not the ambient one. The Actions capture their guard at resolve
            // time precisely so an Action resolved outside `Lukk::onGuard` and invoked inside it
            // can't mint against the wrong identity; reading `currentGuard()` here reintroduced
            // exactly that split — the callback followed one guard and the flag another.
            return self::usesAbilities($context->guard) ? Abilities::fromArray([]) : null;
        }

        $granted = (self::$abilitiesUsing)($userId, $context);

        // A permissions relation returning a Collection is the likeliest real implementation, and a
        // bare `(array)` cast on one yields a nested array — which used to reach `strval()` and
        // 500 every login AND every refresh. Normalize the shapes people actually return.
        //
        // `all()` is an ENUMERABLE method; `Arrayable` declares only `toArray()`. Calling `all()`
        // on the contract was wrong in both directions: an Eloquent model is `Arrayable` with no
        // instance `all()`, so PHP resolved the STATIC `Model::all()` — an unbounded table scan,
        // run inside the rotate transaction's row lock, whose result then landed in a logged
        // exception message; and any other `Arrayable` without an `all()` was a hard fatal on every
        // login and refresh, the exact outage this branch exists to prevent.
        if ($granted instanceof Enumerable) {
            $granted = $granted->all();
        } elseif ($granted instanceof Arrayable) {
            $granted = $granted->toArray();
        }

        return Abilities::fromArray(is_array($granted) ? $granted : [$granted]);
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

    /**
     * Every guard in `config/auth.php` running lukk's driver.
     *
     * The set that MATTERS for isolation, and deliberately not `guardNames()`: a guard becomes real
     * by being declared in `auth.guards` with `driver => lukk-jwt`, whether or not anyone remembered
     * to give it a `lukk.guards` block. Keying the safety check on the lukk block alone meant the
     * dangerous case — a second guard with no block, which therefore inherits the default guard's
     * secret AND audience — was exactly the case the check skipped.
     *
     * @return array<int, string>
     */
    public static function driverGuardNames(): array
    {
        return array_values(array_keys(array_filter(
            (array) config('auth.guards', []),
            fn ($config) => is_array($config) && ($config['driver'] ?? null) === 'lukk-jwt',
        )));
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
        $default = (string) (config('lukk.guard') ?? 'api');

        // A second `lukk-jwt` guard with no `lukk.guards` block gets the default guard's config
        // deep-merged wholesale — same secret, same issuer, same AUDIENCE. Audience is the control
        // that stops one guard's token verifying on another, so cloning it means a customer's token
        // authenticates as whatever the other guard's provider returns for that id: a different user,
        // in a different table, with no boot error and nothing in the log. Refuse to boot.
        foreach (self::driverGuardNames() as $name) {
            if ($name === $default || isset(((array) config('lukk.guards', []))[$name])) {
                continue;
            }

            throw new RuntimeException(
                "lukk guard [{$name}] uses the lukk-jwt driver but has no `lukk.guards.{$name}` "
                ."config block, so it would inherit the [{$default}] guard's secret AND audience — "
                ."and a token minted for [{$default}] would authenticate as a [{$name}] user with "
                .'the same id. Give it its own block with a distinct `audience` (and ideally its own '
                .'`secret`), or drop the guard from config/auth.php.'
            );
        }

        if (! self::isMultiGuard()) {
            return;
        }

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
    public static function actingAs(Authenticatable $user, string $guard = 'api', ?array $abilities = null): void
    {
        app('auth')->guard($guard)->setUser($user);
        app('auth')->shouldUse($guard);

        // Without this, a test acting as a user goes through no guard and therefore leaves no
        // verified token on the request — so `tokenCan()` denies everything and every ability-gated
        // route 401s, which looks like a bug in the route. Pass `['*']` for the common "abilities
        // are not what this test is about" case; pass a narrow list to test the gates themselves.
        if ($abilities !== null) {
            VerifiedToken::assume(new VerifiedToken(
                guard: $guard,
                userId: $user->getAuthIdentifier(),
                userClass: $user::class,
                familyId: 'lukk-acting-as',
                abilities: Abilities::fromArray($abilities),
                // `pin` too: passing an explicit list here IS the pinned semantic, and without it a
                // consumer could not write a passing test for "my narrowly-scoped token must not be
                // able to revoke sessions" using lukk's own helper — the gate would wave it through.
                claims: (object) [
                    'sub' => (string) $user->getAuthIdentifier(),
                    'scope' => Abilities::fromArray($abilities)->toScope(),
                    'pin' => true,
                ],
            ));
        }
    }
}
