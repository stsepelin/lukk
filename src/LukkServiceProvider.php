<?php

declare(strict_types=1);

namespace Lukk;

use Illuminate\Auth\RequestGuard;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Foundation\CachesConfiguration;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Lukk\Actions\AttemptLogin;
use Lukk\Actions\ChallengeTwoFactor;
use Lukk\Actions\ConfirmPassword;
use Lukk\Actions\EnableTwoFactor;
use Lukk\Actions\RegenerateRecoveryCodes;
use Lukk\Actions\RevokeAllSessions;
use Lukk\Actions\RevokeOtherSessions;
use Lukk\Actions\RevokeSession;
use Lukk\Actions\RotateRefreshToken;
use Lukk\Actions\StartSession;
use Lukk\Actions\VerifyTwoFactorChallenge;
use Lukk\Auth\ChallengeToken;
use Lukk\Auth\JwtGuard;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Console\GenerateKeysCommand;
use Lukk\Console\GenerateSecretCommand;
use Lukk\Console\PruneTokensCommand;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\LoginResponse;
use Lukk\Contracts\LogoutResponse;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\RefreshResponse;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Contracts\TokenIssuer;
use Lukk\Contracts\TokenVerifier;
use Lukk\Contracts\TwoFactorChallengeResponse;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Http\Middleware\ForceJsonRequest;
use Lukk\Http\Middleware\RequireConfirmation;
use Lukk\Http\Responses\LoginResponse as LoginResponseImpl;
use Lukk\Http\Responses\LogoutResponse as LogoutResponseImpl;
use Lukk\Http\Responses\RefreshResponse as RefreshResponseImpl;
use Lukk\Http\Responses\TwoFactorChallengeResponse as TwoFactorChallengeResponseImpl;
use Lukk\Passkeys\DatabasePasskeyRepository;
use Lukk\Passkeys\PasskeyChallengeStore;
use Lukk\Passkeys\SpomkyWebAuthnCeremony;
use Lukk\Refresh\DatabaseRefreshTokenRepository;
use Lukk\Support\CacheDenylist;
use Lukk\Support\OptionalDependency;
use Lukk\Tokens\Jwt\FirebaseTokenIssuer;
use Lukk\Tokens\Jwt\FirebaseTokenVerifier;
use Lukk\TwoFactor\Google2FaTotpProvider;
use PragmaRX\Google2FA\Google2FA;
use Webauthn\AuthenticatorAttestationResponseValidator;

class LukkServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigDeep(__DIR__.'/../config/lukk.php', 'lukk');

        $this->registerTokens();
        $this->registerPasskeys();
        $this->registerTwoFactor();
        $this->registerActions();
        $this->registerResponses();
    }

    public function boot(): void
    {
        $this->registerGuard();
        $this->registerRateLimiters();

        $router = $this->app->make('router');
        $router->aliasMiddleware('lukk.confirm', RequireConfirmation::class);
        // Opt-in alias for a consumer's own `auth:api` routes; see docs/installation.md.
        $router->aliasMiddleware('lukk.force-json', ForceJsonRequest::class);

        // `ForceJsonRequest` must sort before `Authenticate` (high in the framework
        // priority). Registered unconditionally so the alias also works in a verify-only
        // service (`routes => false`).
        $kernel = $this->app->make(HttpKernel::class);
        if (method_exists($kernel, 'addToMiddlewarePriorityBefore')) {
            $kernel->addToMiddlewarePriorityBefore(AuthenticatesRequests::class, ForceJsonRequest::class);
        }

        if ($this->config()['routes'] ?? true) {
            $this->loadRoutesFrom(__DIR__.'/routes/api.php');
        }

        $this->callAfterResolving(Schedule::class, function (Schedule $schedule) {
            if (Lukk::$runsScheduledPruning) {
                $schedule->command('lukk:prune')->daily();
            }
        });

        if ($this->app->runningInConsole()) {
            $this->registerPublishing();
            $this->commands([GenerateSecretCommand::class, GenerateKeysCommand::class, PruneTokensCommand::class]);
        }
    }

    /**
     * Core token + revocation seams. Rebind any of these to customize.
     */
    private function registerTokens(): void
    {
        $this->app->singleton(Denylist::class, fn () => new CacheDenylist($this->config()));
        $this->app->singleton(TokenIssuer::class, fn () => new FirebaseTokenIssuer($this->config()));
        $this->app->singleton(TokenVerifier::class, fn ($app) => new FirebaseTokenVerifier($this->config(), $app->make(Denylist::class)));
        $this->app->singleton(ChallengeToken::class, fn ($app) => new ChallengeToken($this->config(), $app->make(Denylist::class)));
        $this->app->singleton(RefreshTokenRepository::class, DatabaseRefreshTokenRepository::class);
    }

    /**
     * Passkey storage, the single-use challenge cache, and the WebAuthn ceremony
     * adapter (resolved only when the passkeys feature is used).
     */
    private function registerPasskeys(): void
    {
        $this->app->singleton(PasskeyRepository::class, DatabasePasskeyRepository::class);

        $this->app->singleton(PasskeyChallengeStore::class, fn () => new PasskeyChallengeStore(
            $this->cacheStore(), (int) $this->config()['passkeys']['challenge_ttl'],
        ));

        $this->app->singleton(WebAuthnCeremony::class, function () {
            OptionalDependency::ensure(AuthenticatorAttestationResponseValidator::class, 'web-auth/webauthn-lib', 'passkeys');

            $passkeys = $this->config()['passkeys'];

            return new SpomkyWebAuthnCeremony([
                'rp_id' => $passkeys['rp_id'],
                'rp_name' => $passkeys['rp_name'] ?? $this->appName(),
                'origins' => $passkeys['origins'],
                'user_verification' => $passkeys['user_verification'] ?? 'preferred',
            ]);
        });
    }

    /**
     * The TOTP provider (resolved only when two-factor is used).
     */
    private function registerTwoFactor(): void
    {
        $this->app->singleton(TwoFactorProvider::class, function () {
            OptionalDependency::ensure(Google2FA::class, 'pragmarx/google2fa', 'two_factor');

            $twoFactor = $this->config()['two_factor'];

            return new Google2FaTotpProvider(new Google2FA, $this->cacheStore(), [
                'issuer' => $twoFactor['issuer'] ?? $this->appName(),
                'window' => (int) $twoFactor['window'],
            ]);
        });
    }

    /**
     * Single-purpose actions, each handed the config slice it needs.
     */
    private function registerActions(): void
    {
        $this->app->bind(StartSession::class, fn ($app) => new StartSession(
            $app->make(RefreshTokenRepository::class), $app->make(TokenIssuer::class), $this->config()));
        $this->app->bind(RevokeSession::class, fn ($app) => new RevokeSession(
            $app->make(RefreshTokenRepository::class), $app->make(Denylist::class), $this->config()));
        $this->app->bind(RevokeAllSessions::class, fn ($app) => new RevokeAllSessions(
            $app->make(RefreshTokenRepository::class), $app->make(Denylist::class), $this->config()));
        $this->app->bind(RevokeOtherSessions::class, fn ($app) => new RevokeOtherSessions(
            $app->make(RefreshTokenRepository::class), $app->make(Denylist::class), $this->config()));
        $this->app->bind(RotateRefreshToken::class, fn ($app) => new RotateRefreshToken(
            $app->make(RefreshTokenRepository::class), $app->make(TokenIssuer::class), $app->make(RevokeSession::class), $this->config()));

        $this->app->bind(LoginRateLimiter::class, fn ($app) => new LoginRateLimiter(
            $app->make(RateLimiter::class),
            (int) $this->config()['rate_limits']['login']['max_attempts'],
            (int) $this->config()['rate_limits']['login']['decay_seconds'],
        ));
        $this->app->bind(AttemptLogin::class, fn ($app) => new AttemptLogin($this->userProvider(), $app->make(LoginRateLimiter::class)));
        $this->app->bind(ConfirmPassword::class, fn () => new ConfirmPassword($this->userProvider()));

        $this->app->bind(EnableTwoFactor::class, fn ($app) => new EnableTwoFactor(
            $app->make(TwoFactorProvider::class), (int) $this->config()['two_factor']['recovery_codes']));
        $this->app->bind(ChallengeTwoFactor::class, fn ($app) => new ChallengeTwoFactor(
            $this->userProvider(), $app->make(TwoFactorProvider::class)));
        $this->app->bind(VerifyTwoFactorChallenge::class, fn ($app) => new VerifyTwoFactorChallenge(
            $app->make(ChallengeToken::class), $app->make(ChallengeTwoFactor::class), $app->make(RateLimiter::class),
            (int) $this->config()['rate_limits']['two_factor']['max_attempts'],
            (int) $this->config()['rate_limits']['two_factor']['decay_seconds'],
        ));
        $this->app->bind(RegenerateRecoveryCodes::class, fn () => new RegenerateRecoveryCodes(
            (int) $this->config()['two_factor']['recovery_codes']));
    }

    /**
     * Response contracts — rebind any to reshape the body/cookies.
     */
    private function registerResponses(): void
    {
        $this->app->bind(LoginResponse::class, LoginResponseImpl::class);
        $this->app->bind(RefreshResponse::class, RefreshResponseImpl::class);
        $this->app->bind(LogoutResponse::class, LogoutResponseImpl::class);
        $this->app->bind(TwoFactorChallengeResponse::class, TwoFactorChallengeResponseImpl::class);
    }

    private function registerGuard(): void
    {
        Auth::extend('lukk-jwt', function ($app, $name, array $config) {
            $provider = $app->make('auth')->createUserProvider($config['provider'] ?? null);
            $guard = new JwtGuard($app->make(TokenVerifier::class), $provider);

            return new RequestGuard(fn ($request) => $guard($request), $app->make('request'), $provider);
        });
    }

    /**
     * Named, config-driven per-IP throttles for the public endpoints (login also
     * uses its own per-account failure limiter; 2FA also throttles per account in
     * the action). The `?? ` defaults guard a stale published config: mergeConfigFrom
     * doesn't deep-merge nested arrays, so a missing key would resolve to 0 — and
     * `Limit(0)` would lock everyone out.
     */
    private function registerRateLimiters(): void
    {
        $limiter = $this->app->make(RateLimiter::class);

        foreach (['refresh' => 'lukk-refresh', 'passkeys' => 'lukk-passkeys', 'two_factor' => 'lukk-2fa'] as $key => $name) {
            $limiter->for($name, function ($request) use ($key) {
                $limit = (array) ($this->config()['rate_limits'][$key] ?? []);

                return (new Limit(maxAttempts: (int) ($limit['max_attempts'] ?? 30), decaySeconds: (int) ($limit['decay_seconds'] ?? 60)))
                    ->by($request->ip());
            });
        }

        $limiter->for('lukk-login', function ($request) {
            $limit = (array) ($this->config()['rate_limits']['login'] ?? []);

            return (new Limit(maxAttempts: (int) ($limit['ip_max_attempts'] ?? 30), decaySeconds: (int) ($limit['decay_seconds'] ?? 60)))
                ->by($request->ip());
        });
    }

    private function registerPublishing(): void
    {
        $this->publishes([__DIR__.'/../config/lukk.php' => config_path('lukk.php')], 'lukk-config');

        // Migrations are publish-only (Sanctum/Passport convention); each optional
        // feature is its own group so you only add its schema when you enable it.
        // The 2FA columns target the app's own users table — publish, never auto-run.
        $this->publishesMigrations([__DIR__.'/../database/migrations' => database_path('migrations')], 'lukk-migrations');
        $this->publishesMigrations([__DIR__.'/../database/two-factor' => database_path('migrations')], 'lukk-two-factor-migrations');
        $this->publishesMigrations([__DIR__.'/../database/passkeys' => database_path('migrations')], 'lukk-passkey-migrations');
    }

    /**
     * Like mergeConfigFrom, but deep: a stale published config (missing nested keys
     * the package added later) is backfilled from the defaults. mergeConfigFrom only
     * merges the first dimension, so a published nested array would otherwise replace
     * the package default wholesale and a missing key would resolve to null.
     */
    protected function mergeConfigDeep(string $path, string $key): void
    {
        if ($this->app instanceof CachesConfiguration && $this->app->configurationIsCached()) {
            return;
        }

        $config = $this->app->make('config');
        $config->set($key, self::mergeConfig(require $path, $config->get($key, [])));
    }

    /**
     * Recursively fill keys absent from $config with the $defaults. Associative
     * sub-blocks recurse; lists (origins/audience) and scalars are replaced by the
     * app's value when present.
     *
     * @param  array<mixed>  $defaults
     * @param  array<mixed>  $config
     * @return array<mixed>
     */
    public static function mergeConfig(array $defaults, array $config): array
    {
        foreach ($defaults as $key => $default) {
            if (is_array($default) && ! array_is_list($default) && is_array($config[$key] ?? null)) {
                $config[$key] = self::mergeConfig($default, $config[$key]);
            } elseif (! array_key_exists($key, $config)) {
                $config[$key] = $default;
            }
        }

        return $config;
    }

    /**
     * The `lukk` config block.
     *
     * @return array<string, mixed>
     */
    private function config(): array
    {
        return $this->app->make('config')->get('lukk');
    }

    private function appName(): string
    {
        return $this->app->make('config')->get('app.name', 'Laravel');
    }

    private function cacheStore(): CacheRepository
    {
        return $this->app->make('cache')->store($this->config()['denylist_store'] ?? null);
    }

    private function userProvider(): ?UserProvider
    {
        return $this->app->make('auth')->createUserProvider($this->config()['user_provider'] ?? null);
    }
}
