<?php

declare(strict_types=1);

namespace Lukk;

use Illuminate\Auth\Notifications\ResetPassword as ResetPasswordNotification;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Auth\RequestGuard;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesConfiguration;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;
use Lukk\Actions\AttemptLogin;
use Lukk\Actions\ChallengeTwoFactor;
use Lukk\Actions\ChangePassword;
use Lukk\Actions\ConfirmPassword;
use Lukk\Actions\DeleteAccount;
use Lukk\Actions\EnableTwoFactor;
use Lukk\Actions\ExportAccount;
use Lukk\Actions\FinishPasskeyLogin;
use Lukk\Actions\RegenerateRecoveryCodes;
use Lukk\Actions\Register;
use Lukk\Actions\ResetPassword;
use Lukk\Actions\RevokeAllSessions;
use Lukk\Actions\RevokeOtherSessions;
use Lukk\Actions\RevokeSession;
use Lukk\Actions\RotateRefreshToken;
use Lukk\Actions\SendPasswordResetLink;
use Lukk\Actions\StartSession;
use Lukk\Actions\VerifyTwoFactorChallenge;
use Lukk\Auth\ChallengeToken;
use Lukk\Auth\JwtGuard;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Console\GenerateKeysCommand;
use Lukk\Console\GenerateSecretCommand;
use Lukk\Console\PruneTokensCommand;
use Lukk\Console\ReleaseLockoutCommand;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\EmailVerificationResponse;
use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\LoginResponse;
use Lukk\Contracts\LogoutResponse;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\RefreshResponse;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Contracts\RegisterResponse;
use Lukk\Contracts\TokenIssuer;
use Lukk\Contracts\TokenVerifier;
use Lukk\Contracts\TwoFactorChallengeResponse;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Guards\GuardContext;
use Lukk\Http\Controllers\PasskeyAuthenticatedSessionController;
use Lukk\Http\Middleware\ForceJsonRequest;
use Lukk\Http\Middleware\RequireAbility;
use Lukk\Http\Middleware\RequireAllAbilities;
use Lukk\Http\Middleware\RequireConfirmation;
use Lukk\Http\Middleware\RequirePinnedAbility;
use Lukk\Http\Middleware\RequireVerifiedEmail;
use Lukk\Http\Middleware\SetGuard;
use Lukk\Http\Responses\EmailVerificationResponse as EmailVerificationResponseImpl;
use Lukk\Http\Responses\LoginResponse as LoginResponseImpl;
use Lukk\Http\Responses\LogoutResponse as LogoutResponseImpl;
use Lukk\Http\Responses\RefreshResponse as RefreshResponseImpl;
use Lukk\Http\Responses\RegisterResponse as RegisterResponseImpl;
use Lukk\Http\Responses\TwoFactorChallengeResponse as TwoFactorChallengeResponseImpl;
use Lukk\Lockout\DatabaseLockoutRepository;
use Lukk\Passkeys\DatabasePasskeyRepository;
use Lukk\Passkeys\PasskeyChallengeStore;
use Lukk\Passkeys\SpomkyWebAuthnCeremony;
use Lukk\Refresh\DatabaseRefreshTokenRepository;
use Lukk\Support\CacheDenylist;
use Lukk\Support\CacheStoreGuard;
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
        Lukk::assertGuardsIsolated();
        $this->registerRateLimiters();

        $router = $this->app->make('router');
        $router->aliasMiddleware('lukk.confirm', RequireConfirmation::class);
        // `lukk.ability:a,b` = any of them; `lukk.abilities:a,b` = all of them (Sanctum's split).
        $router->aliasMiddleware('lukk.ability', RequireAbility::class);
        $router->aliasMiddleware('lukk.abilities', RequireAllAbilities::class);
        $router->aliasMiddleware('lukk.verified', RequireVerifiedEmail::class);
        // Opt-in alias for a consumer's own `auth:api` routes; see docs/installation.md.
        $router->aliasMiddleware('lukk.force-json', ForceJsonRequest::class);
        // Stamps the active guard per per-guard route group (multi-guard).
        $router->aliasMiddleware('lukk.set-guard', SetGuard::class);

        // `ForceJsonRequest` must sort before `Authenticate` (high in the framework
        // priority). Registered unconditionally so the alias also works in a verify-only
        // service (`routes => false`).
        $kernel = $this->app->make(HttpKernel::class);
        if (method_exists($kernel, 'addToMiddlewarePriorityBefore')) {
            $kernel->addToMiddlewarePriorityBefore(AuthenticatesRequests::class, ForceJsonRequest::class);
        }

        // The ability gates read the token the guard put on the request, so they are meaningless
        // before `auth:api` has run. Middleware executes in the order listed on the route unless it
        // appears in the priority list, and `Authenticate` does — so a route written
        // `['lukk.ability:orders.read', 'auth:api']` would otherwise gate first and answer 401 on a
        // perfectly good token. Sorting them after `Authenticate` makes the declaration order on
        // the route stop mattering.
        if (method_exists($kernel, 'addToMiddlewarePriorityAfter')) {
            $kernel->addToMiddlewarePriorityAfter(AuthenticatesRequests::class, RequireAbility::class);
            $kernel->addToMiddlewarePriorityAfter(RequireAbility::class, RequireAllAbilities::class);
            // Same reason: it reads the authenticated user, and a null one makes it a silent no-op.
            $kernel->addToMiddlewarePriorityAfter(RequireAllAbilities::class, RequirePinnedAbility::class);
        }

        if ($this->config()['routes'] ?? true) {
            $this->loadRoutesFrom(__DIR__.'/routes/api.php');

            // Point the notification at the signed verify route — but only when that route is
            // actually registered (i.e. lukk owns the routes). Otherwise a verify-only service
            // (`routes => false`) with the feature on would reference a missing route name.
            if ($this->config()['features']['email_verification'] ?? false) {
                $this->configureEmailVerification();
            }

            if ($this->config()['features']['password_reset'] ?? false) {
                $this->configurePasswordReset();
            }
        }

        $this->callAfterResolving(Schedule::class, function (Schedule $schedule) {
            if (Lukk::$runsScheduledPruning) {
                $schedule->command('lukk:prune')->daily();
            }
        });

        if ($this->app->runningInConsole()) {
            $this->registerPublishing();
            $this->commands([GenerateSecretCommand::class, GenerateKeysCommand::class, PruneTokensCommand::class, ReleaseLockoutCommand::class]);
        }
    }

    /**
     * Core token + revocation seams. Rebind any of these to customize.
     */
    private function registerTokens(): void
    {
        // The active-guard holder (scoped → reset per request in Octane; per-request in FPM) + a
        // shared denylist (jti/fid are UUIDs, so revocation entries never collide across guards).
        $this->app->scoped(GuardContext::class);
        $this->app->singleton(Denylist::class, fn () => new CacheDenylist($this->config()));

        // Per-guard crypto identity: each resolves from the CURRENT guard's config (its own
        // secret/keys/issuer/audience/ttls), so a token minted for one guard can't be issued or
        // verified as another. Bind (not singleton) so the current guard is honored per request.
        $this->app->bind(TokenIssuer::class, fn () => new FirebaseTokenIssuer(Lukk::guardConfig()));
        $this->app->bind(TokenVerifier::class, fn ($app) => new FirebaseTokenVerifier(Lukk::guardConfig(), $app->make(Denylist::class)));
        $this->app->bind(ChallengeToken::class, fn ($app) => new ChallengeToken(Lukk::guardConfig(), $app->make(Denylist::class)));
        $this->app->bind(RefreshTokenRepository::class, fn () => new DatabaseRefreshTokenRepository(
            Lukk::isMultiGuard() ? Lukk::currentGuard() : null));
    }

    /**
     * Passkey storage, the single-use challenge cache, and the WebAuthn ceremony
     * adapter (resolved only when the passkeys feature is used).
     */
    private function registerPasskeys(): void
    {
        // `bind`, not `singleton`, and guard-scoped exactly like the refresh-token repository: the
        // active guard is per-request, so a memoized instance would carry the previous request's
        // guard into the next one.
        $this->app->bind(PasskeyRepository::class, fn () => new DatabasePasskeyRepository(
            Lukk::isMultiGuard() ? Lukk::currentGuard() : null));

        // The controller needs THIS guard's user provider, which is not a resolvable type — same
        // reason the actions below are bound explicitly rather than autowired.
        $this->app->bind(PasskeyAuthenticatedSessionController::class, fn ($app) => new PasskeyAuthenticatedSessionController(
            $app->make(FinishPasskeyLogin::class), $app->make(StartSession::class),
            $this->userProviderFor(Lukk::currentGuard()),
        ));

        // Bound explicitly rather than auto-resolved: the nullable `?LockoutRepository` means
        // "feature off", and the container would happily inject the always-bound repository and
        // make that distinction disappear.
        $this->app->bind(FinishPasskeyLogin::class, fn ($app) => new FinishPasskeyLogin(
            $app->make(PasskeyChallengeStore::class), $app->make(WebAuthnCeremony::class),
            $app->make(PasskeyRepository::class), $this->lockouts($app), Lukk::currentGuard(),
        ));

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
                'user_verification' => $passkeys['user_verification'] ?? 'required',
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
        // Session/rotation/revocation actions run against the CURRENT guard's config + (via the
        // bindings above) its issuer + guard-scoped repository — so a session is minted, rotated,
        // and revoked entirely within one guard's family of tokens.
        // Bound explicitly: the nullable passkey/lockout repositories mean "that feature is off", and
        // the container would inject the always-bound implementations and erase the distinction.
        // The optional repositories are injected UNCONDITIONALLY here, unlike everywhere else in this
        // provider where a null means "feature off". Erasure is about rows that EXIST, and a feature
        // switched off after use leaves its rows behind — orphaned personal data, while the user row
        // itself is deleted. `DeleteAccount` guards on the table existing instead.
        $this->app->bind(DeleteAccount::class, fn ($app) => new DeleteAccount(
            $app->make(RefreshTokenRepository::class),
            $app->make(RevokeAllSessions::class),
            $app->make(PasskeyRepository::class),
            $app->make(LockoutRepository::class),
            (string) ($this->config()['username'] ?? 'email'),
            Lukk::currentGuard(),
            $this->config()['password_reset']['broker'] ?? null,
        ));

        $this->app->bind(ExportAccount::class, fn ($app) => new ExportAccount(
            $app->make(RefreshTokenRepository::class),
            $app->make(PasskeyRepository::class),
            (string) ($this->config()['username'] ?? 'email'),
        ));

        $this->app->bind(StartSession::class, fn ($app) => new StartSession(
            $app->make(RefreshTokenRepository::class), $app->make(TokenIssuer::class), Lukk::guardConfig(), Lukk::currentGuard()));
        $this->app->bind(RevokeSession::class, fn ($app) => new RevokeSession(
            $app->make(RefreshTokenRepository::class), $app->make(Denylist::class), Lukk::guardConfig()));
        $this->app->bind(RevokeAllSessions::class, fn ($app) => new RevokeAllSessions(
            $app->make(RefreshTokenRepository::class), $app->make(Denylist::class), Lukk::guardConfig()));
        $this->app->bind(RevokeOtherSessions::class, fn ($app) => new RevokeOtherSessions(
            $app->make(RefreshTokenRepository::class), $app->make(Denylist::class), Lukk::guardConfig()));
        $this->app->bind(RotateRefreshToken::class, fn ($app) => new RotateRefreshToken(
            $app->make(RefreshTokenRepository::class), $app->make(TokenIssuer::class),
            $app->make(RevokeSession::class), $app->make(Denylist::class), Lukk::guardConfig(), Lukk::currentGuard()));

        $this->app->bind(LoginRateLimiter::class, fn ($app) => new LoginRateLimiter(
            $app->make(RateLimiter::class),
            (int) ($this->config()['rate_limits']['login']['max_attempts'] ?? 5),
            (int) ($this->config()['rate_limits']['login']['decay_seconds'] ?? 60),
            (int) ($this->config()['rate_limits']['login']['account_max_attempts'] ?? 20),
            (string) ($this->config()['username'] ?? 'email'),
            Lukk::currentGuard(),
        ));
        // Login/confirm resolve the CURRENT guard's user provider (from config/auth.php), so the
        // admin login authenticates against the admins table, not the users table.
        $this->app->bind(LockoutRepository::class, function () {
            $lockout = (array) ($this->config()['lockout'] ?? []);
            // A non-numeric env value is truthy but casts to 0, and `attempts >= 0` would lock every
            // account on its owner's first typo — the `Limit(0)` failure class this package already
            // guards elsewhere. 100 is also §5.2.2's ceiling, so clamp rather than trust.
            $max = is_numeric($lockout['max_attempts'] ?? null) ? (int) $lockout['max_attempts'] : 100;
            $after = is_numeric($lockout['release_after'] ?? null) ? (int) $lockout['release_after'] : 0;

            return new DatabaseLockoutRepository(max(1, min(100, $max)), max(0, $after));
        });

        $this->app->bind(AttemptLogin::class, fn ($app) => new AttemptLogin(
            $this->userProviderFor(Lukk::currentGuard()), $app->make(LoginRateLimiter::class), $this->lockouts($app)));
        $this->app->bind(ChangePassword::class, fn ($app) => new ChangePassword(
            $this->userProviderFor(Lukk::currentGuard()), $app->make(RevokeOtherSessions::class),
            $app->make(RevokeAllSessions::class), $this->lockouts($app), Lukk::currentGuard()));
        $this->app->bind(ConfirmPassword::class, fn ($app) => new ConfirmPassword(
            $this->userProviderFor(Lukk::currentGuard()), $this->lockouts($app), Lukk::currentGuard()));
        $this->app->bind(SendPasswordResetLink::class, fn () => new SendPasswordResetLink($this->config()['password_reset']['broker'] ?? null));
        $this->app->bind(ResetPassword::class, fn ($app) => new ResetPassword(
            $app->make(RevokeAllSessions::class), $this->config(), $this->lockouts($app), Lukk::currentGuard()));
        $this->app->bind(Register::class, fn () => new Register(
            $this->userModelClass(), (string) ($this->config()['username'] ?? 'email')));

        $this->app->bind(EnableTwoFactor::class, fn ($app) => new EnableTwoFactor(
            $app->make(TwoFactorProvider::class), (int) $this->config()['two_factor']['recovery_codes']));
        $this->app->bind(ChallengeTwoFactor::class, fn ($app) => new ChallengeTwoFactor(
            $this->userProviderFor(Lukk::currentGuard()), $app->make(TwoFactorProvider::class)));
        $this->app->bind(VerifyTwoFactorChallenge::class, fn ($app) => new VerifyTwoFactorChallenge(
            $app->make(ChallengeToken::class), $app->make(ChallengeTwoFactor::class), $app->make(RateLimiter::class),
            (int) $this->config()['rate_limits']['two_factor']['max_attempts'],
            (int) $this->config()['rate_limits']['two_factor']['decay_seconds'],
            $this->lockouts($app), Lukk::currentGuard(),
        ));
        $this->app->bind(RegenerateRecoveryCodes::class, fn () => new RegenerateRecoveryCodes(
            (int) $this->config()['two_factor']['recovery_codes']));
    }

    /**
     * Response contracts — rebind any to reshape the body/cookies.
     */
    /**
     * Point Laravel's email-verification notification at lukk's signed verify route, so
     * the link the user clicks lands on lukk's endpoint (which then redirects to your SPA).
     * Only wired when the feature is on, so a host app's own verification isn't hijacked.
     */
    private function configureEmailVerification(): void
    {
        VerifyEmail::createUrlUsing(fn ($notifiable) => URL::temporarySignedRoute(
            'lukk.verification.verify',
            now()->addMinutes((int) ($this->config()['email_verification']['expire'] ?? 60)),
            ['id' => $notifiable->getKey(), 'hash' => sha1($notifiable->getEmailForVerification())],
        ));
    }

    /**
     * Point Laravel's password-reset notification at your SPA reset page (with the token +
     * email in the query), rather than the framework-default web route. Only wired when the
     * feature is on, so a host app's own password reset isn't hijacked. The link carries the
     * broker token; the SPA page collects the new password and POSTs it to `/auth/reset-password`.
     */
    private function configurePasswordReset(): void
    {
        ResetPasswordNotification::createUrlUsing(function ($notifiable, string $token): string {
            $frontend = (string) ($this->config()['password_reset']['frontend_url'] ?? '');

            return $frontend.(str_contains($frontend, '?') ? '&' : '?')
                .'token='.$token.'&email='.urlencode($notifiable->getEmailForPasswordReset());
        });
    }

    private function registerResponses(): void
    {
        $this->app->bind(LoginResponse::class, LoginResponseImpl::class);
        $this->app->bind(RefreshResponse::class, RefreshResponseImpl::class);
        $this->app->bind(LogoutResponse::class, LogoutResponseImpl::class);
        $this->app->bind(TwoFactorChallengeResponse::class, TwoFactorChallengeResponseImpl::class);
        $this->app->bind(EmailVerificationResponse::class, EmailVerificationResponseImpl::class);
        $this->app->bind(RegisterResponse::class, RegisterResponseImpl::class);
    }

    private function registerGuard(): void
    {
        Auth::extend('lukk-jwt', function ($app, $name, array $config) {
            $provider = $app->make('auth')->createUserProvider($config['provider'] ?? null);

            // Verify with THIS guard's own crypto identity (its secret/keys + audience allowlist),
            // resolved by the guard name — never the shared/current-guard verifier. A token minted
            // for another guard fails the audience (and signature, if keys differ) check and returns
            // null before any user is resolved (reject-before-resolve, per RFC 8725 §3.9).
            $verifier = new FirebaseTokenVerifier(Lukk::guardConfig($name), $app->make(Denylist::class));
            $guard = new JwtGuard($verifier, $provider, $name);

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

        foreach (['refresh' => 'lukk-refresh', 'passkeys' => 'lukk-passkeys', 'two_factor' => 'lukk-2fa', 'email_verification' => 'lukk-email-verification', 'password_reset' => 'lukk-password-reset', 'registration' => 'lukk-register', 'confirm' => 'lukk-confirm'] as $key => $name) {
            $limiter->for($name, function ($request) use ($key, $name) {
                $limit = (array) ($this->config()['rate_limits'][$key] ?? []);
                $max = (int) ($limit['max_attempts'] ?? 30);
                $decay = (int) ($limit['decay_seconds'] ?? 60);

                $limits = [(new Limit(maxAttempts: $max, decaySeconds: $decay))->by(Lukk::rateLimitKey($request))];

                // Per-IP alone stops bounding an AUTHENTICATED endpoint once the address is genuinely
                // the visitor's: rotating IPs is cheap, so bucket on the identity the endpoint acts
                // on as well. Laravel applies every limit returned, so the tighter of the two wins.
                // For step-up confirmation the per-user bucket is the load-bearing one — a caller
                // with a stolen token is a single identity behind however many addresses they like.
                //
                // Guard-scoped, and resolved from lukk's own guard: the same limiter also guards the
                // UNAUTHENTICATED signed verify route, where `$request->user()` would otherwise
                // resolve the app's default guard and share a bucket with a colliding id from an
                // unrelated provider — the isolation lukk's multi-guard work exists to prevent.
                //
                // Deliberately NOT mirrored on registration: a duplicate signup is a 422 from the
                // `unique` rule and sends no mail, so an identity bucket there would bound nothing —
                // while handing anyone a remote, IP-independent way to deny a chosen address the
                // ability to register at all.
                // Resolved ONLY for this limiter: touching the auth manager for the others would
                // resolve a guard before their own middleware runs. And `user($guard)` THROWS for a
                // guard the app hasn't declared — this limiter also fronts the public signed verify
                // route, so that would turn a misconfiguration into a 500 on an anonymous endpoint.
                if ($key === 'email_verification' || $key === 'confirm') {
                    $guard = Lukk::currentGuard();
                    $user = isset(config('auth.guards')[$guard]) ? $request->user($guard) : null;

                    if ($user !== null) {
                        $limits[] = (new Limit(maxAttempts: $max, decaySeconds: $decay))
                            ->by($name.'|'.$guard.'|user|'.$user->getAuthIdentifier());
                    }
                }

                return $limits;
            });
        }

        $limiter->for('lukk-login', function ($request) {
            $limit = (array) ($this->config()['rate_limits']['login'] ?? []);

            return (new Limit(maxAttempts: (int) ($limit['ip_max_attempts'] ?? 30), decaySeconds: (int) ($limit['decay_seconds'] ?? 60)))
                ->by(Lukk::rateLimitKey($request));
        });

        // Per-guard login/refresh limiters for the additional guards' core-session routes, so an
        // admin login flood can't consume the users guard's budget (each keyed per IP).
        foreach (array_keys((array) ($this->config()['guards'] ?? [])) as $guardName) {
            $limits = (array) (Lukk::guardConfig((string) $guardName)['rate_limits'] ?? []);

            $limiter->for("lukk-{$guardName}-login", fn ($request) => (new Limit(
                maxAttempts: (int) ($limits['login']['ip_max_attempts'] ?? 30),
                decaySeconds: (int) ($limits['login']['decay_seconds'] ?? 60)))->by(Lukk::rateLimitKey($request)));

            $limiter->for("lukk-{$guardName}-refresh", fn ($request) => (new Limit(
                maxAttempts: (int) ($limits['refresh']['max_attempts'] ?? 30),
                decaySeconds: (int) ($limits['refresh']['decay_seconds'] ?? 60)))->by(Lukk::rateLimitKey($request)));

            // The two-factor challenge is mounted per guard wherever that guard enables the feature,
            // so it needs its own bucket. Registered unconditionally: a limiter attached to a route
            // that never mounts is inert, whereas a route mounted against a MISSING limiter is a
            // 500 on the endpoint standing between a user and their account.
            $limiter->for("lukk-{$guardName}-2fa", fn ($request) => (new Limit(
                maxAttempts: (int) ($limits['two_factor']['max_attempts'] ?? 30),
                decaySeconds: (int) ($limits['two_factor']['decay_seconds'] ?? 60)))->by(Lukk::rateLimitKey($request)));

            // The extra guards carry confirm-password too, and they need the SAME per-user bucket as
            // the default guard — these are the higher-privilege audiences multi-guard exists for,
            // so per-IP alone would hand a thief with a stolen admin token 5 password guesses per
            // source /64 per minute. This limiter is attached to exactly one route, inside this
            // guard's own group, after `lukk.set-guard:{$guardName}` and after `auth:{$guardName}`
            // (framework priority runs AuthenticatesRequests before ThrottleRequests), so resolving
            // this guard's user here is both correct and the only guard it can touch.
            $limiter->for("lukk-{$guardName}-confirm", function ($request) use ($guardName, $limits) {
                $max = (int) ($limits['confirm']['max_attempts'] ?? 5);
                $decay = (int) ($limits['confirm']['decay_seconds'] ?? 60);

                $out = [(new Limit(maxAttempts: $max, decaySeconds: $decay))->by(Lukk::rateLimitKey($request))];
                $user = isset(config('auth.guards')[$guardName]) ? $request->user($guardName) : null;

                if ($user !== null) {
                    $out[] = (new Limit(maxAttempts: $max, decaySeconds: $decay))
                        ->by("lukk-{$guardName}-confirm|{$guardName}|user|".$user->getAuthIdentifier());
                }

                return $out;
            });
        }
    }

    /** The lockout store, or null when `features.lockout` is off — the actions no-op on null. */
    private function lockouts(Application $app): ?LockoutRepository
    {
        return ($this->config()['features']['lockout'] ?? false) ? $app->make(LockoutRepository::class) : null;
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
        $this->publishesMigrations([__DIR__.'/../database/lockout' => database_path('migrations')], 'lukk-lockout-migrations');
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
        $store = $this->app->make('cache')->store($this->config()['denylist_store'] ?? null);

        CacheStoreGuard::assertCanHoldRevocations($store);

        return $store;
    }

    /**
     * The user provider for a given guard. The default guard uses `lukk.user_provider`; an extra
     * guard reuses its `config/auth.php` provider (single source of truth) — so lukk never
     * duplicates the provider, and login resolves the right table per guard.
     */
    private function userProviderFor(string $guard): UserProvider
    {
        $config = $this->app->make('config');

        $provider = $guard === (string) ($this->config()['guard'] ?? 'api')
            ? ($this->config()['user_provider'] ?? null)
            : ($config->get("auth.guards.{$guard}.provider") ?? $this->config()['user_provider'] ?? null);

        $resolved = $this->app->make('auth')->createUserProvider($provider);

        // Null only when the named provider is not configured at all — a typo in `auth.providers`.
        // Nothing validates that at boot (`assertGuardsIsolated` checks driver/audience/path/domain,
        // NOT provider names), so this is a genuine assertion rather than a restatement of an
        // earlier guard. With assertions compiled out it degrades to a TypeError on the return,
        // which is the same loud failure one frame later.
        assert($resolved !== null);

        return $resolved;
    }

    /**
     * The Eloquent user model behind the configured provider — the default target for
     * registration's create (used only when no Lukk::registerUsing hook is set).
     *
     * @return class-string
     */
    private function userModelClass(): string
    {
        $provider = $this->config()['user_provider'] ?? 'users';

        /** @var class-string $model */
        $model = (string) $this->app->make('config')->get("auth.providers.{$provider}.model");

        return $model;
    }
}
