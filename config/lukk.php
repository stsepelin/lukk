<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Signing Algorithm
    |--------------------------------------------------------------------------
    |
    | HS256 is correct while this application is the sole verifier of its own
    | tokens (no keypair, no JWKS). Switch to RS256/ES256 with a keypair only
    | when an independent service must verify tokens without sharing the secret.
    |
    */

    'algorithm' => env('LUKK_ALGORITHM', 'HS256'),

    /*
    |--------------------------------------------------------------------------
    | Signing Secret
    |--------------------------------------------------------------------------
    |
    | The 256-bit random key used to sign access tokens. Generate one and write
    | it to your .env file by running: `php artisan lukk:secret`
    |
    */

    'secret' => env('LUKK_SECRET'),

    /*
    |--------------------------------------------------------------------------
    | Asymmetric Keys (RS256 / ES256)
    |--------------------------------------------------------------------------
    |
    | Used only when "algorithm" is asymmetric. The private key signs (stamping
    | "active" as the kid); the "public" map is the kid-addressed verification
    | set. To rotate without forcing logouts, generate a new key, add it to
    | "public", point "active" at it, and keep the old public key listed until
    | its last token has expired. Each value may be an inline PEM or a path.
    |
    */

    'keys' => [
        'active' => env('LUKK_ACTIVE_KID', 'default'),

        'private' => env('LUKK_PRIVATE_KEY'),

        'passphrase' => env('LUKK_KEY_PASSPHRASE'),

        'public' => array_filter([
            env('LUKK_ACTIVE_KID', 'default') => env('LUKK_PUBLIC_KEY'),
        ]),
    ],

    /*
    |--------------------------------------------------------------------------
    | Issuer & Audience
    |--------------------------------------------------------------------------
    |
    | The "iss" and "aud" claims stamped into every access token and validated
    | on each request. They identify who minted the token and who it is for.
    |
    | LUKK_AUDIENCE is comma-separated: list several services to mint one token
    | for all of them, and each accepts it when its own audience is in the list.
    | A single audience is stamped as a plain string. See "Deployment".
    |
    */

    'issuer' => env('LUKK_ISSUER', 'https://api.example.com'),
    'audience' => array_values(array_filter(array_map('trim', explode(',', (string) env('LUKK_AUDIENCE', 'https://api.example.com'))))),

    /*
    |--------------------------------------------------------------------------
    | Token Lifetimes
    |--------------------------------------------------------------------------
    |
    | The lifetime (in seconds) of the short-lived access token and the opaque
    | rotating refresh token. Access tokens are intentionally brief; refresh
    | tokens persist for the duration of a remembered session. The defaults are
    | 15 minutes and 30 days.
    |
    */

    'access_ttl' => (int) env('LUKK_ACCESS_TTL', 900),
    'refresh_ttl' => (int) env('LUKK_REFRESH_TTL', 2592000),

    /*
    |--------------------------------------------------------------------------
    | Refresh Grace Window
    |--------------------------------------------------------------------------
    |
    | The overlap window (in seconds) during which a just-rotated token is
    | still tolerated, so concurrent refreshes (multi-tab / SSR) do not trip
    | reuse detection and force a false-positive logout.
    |
    */

    'grace_seconds' => (int) env('LUKK_GRACE', 30),

    /*
    |--------------------------------------------------------------------------
    | Clock Skew Leeway
    |--------------------------------------------------------------------------
    |
    | The tolerance (in seconds) applied when validating the "exp" and "nbf"
    | claims, absorbing minor clock drift between machines.
    |
    */

    'leeway' => (int) env('LUKK_LEEWAY', 5),

    /*
    |--------------------------------------------------------------------------
    | Rate Limits
    |--------------------------------------------------------------------------
    |
    | Every throttle in one place, each as { max_attempts, decay_seconds }.
    |
    */

    'rate_limits' => [

        /*
        |--------------------------------------------------------------------------
        | Login
        |--------------------------------------------------------------------------
        |
        | The failures-only limiter: only failed attempts count, a success clears
        | the counter. "max_attempts" is keyed on the normalized email + IP (the
        | tight per-origin limit); "account_max_attempts" is keyed on the email
        | alone — an IP-independent cap so a distributed attacker can't get
        | "max_attempts" guesses per IP against one account (keep it above
        | max_attempts for legit multi-device users). "ip_max_attempts" is a
        | separate coarse per-IP cap on ALL login requests, so password spraying
        | (varying the email) can't slip past the per-account limit.
        |
        */

        'login' => [
            'max_attempts' => (int) env('LUKK_LOGIN_MAX_ATTEMPTS', 5),
            'decay_seconds' => (int) env('LUKK_LOGIN_DECAY', 60),
            'ip_max_attempts' => (int) env('LUKK_LOGIN_IP_MAX_ATTEMPTS', 30),
            'account_max_attempts' => (int) env('LUKK_LOGIN_ACCOUNT_MAX_ATTEMPTS', 20),
        ],

        /*
        |--------------------------------------------------------------------------
        | Two-Factor
        |--------------------------------------------------------------------------
        |
        | Feeds two limiters: a per-IP cap on the challenge route, and the real
        | per-account guess limit (keyed by "sub") enforced inside the verify
        | action.
        |
        */

        'two_factor' => [
            'max_attempts' => (int) env('LUKK_2FA_MAX_ATTEMPTS', 5),
            'decay_seconds' => (int) env('LUKK_2FA_DECAY', 60),
        ],

        /*
        |--------------------------------------------------------------------------
        | Refresh
        |--------------------------------------------------------------------------
        |
        | A per-IP guard on the token-refresh endpoint.
        |
        */

        'refresh' => [
            'max_attempts' => (int) env('LUKK_REFRESH_MAX_ATTEMPTS', 30),
            'decay_seconds' => (int) env('LUKK_REFRESH_DECAY', 60),
        ],

        /*
        |--------------------------------------------------------------------------
        | Passkeys
        |--------------------------------------------------------------------------
        |
        | A per-IP guard on the passkey login/registration endpoints.
        |
        */

        'passkeys' => [
            'max_attempts' => (int) env('LUKK_PASSKEY_MAX_ATTEMPTS', 30),
            'decay_seconds' => (int) env('LUKK_PASSKEY_DECAY', 60),
        ],

        /*
        |--------------------------------------------------------------------------
        | Email Verification
        |--------------------------------------------------------------------------
        |
        | A per-IP guard on the verify + resend endpoints.
        |
        */

        'email_verification' => [
            'max_attempts' => (int) env('LUKK_VERIFY_MAX_ATTEMPTS', 6),
            'decay_seconds' => (int) env('LUKK_VERIFY_DECAY', 60),
        ],

        /*
        |--------------------------------------------------------------------------
        | Password Reset
        |--------------------------------------------------------------------------
        |
        | A per-IP guard on the forgot-password + reset-password endpoints.
        |
        */

        'password_reset' => [
            'max_attempts' => (int) env('LUKK_RESET_MAX_ATTEMPTS', 6),
            'decay_seconds' => (int) env('LUKK_RESET_DECAY', 60),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Two-Factor Authentication
    |--------------------------------------------------------------------------
    |
    | TOTP-based two-factor settings. Requires the "two_factor" feature to be
    | enabled below and the pragmarx/google2fa package to be installed.
    |
    */

    'two_factor' => [

        /*
        |--------------------------------------------------------------------------
        | Authenticator Label
        |--------------------------------------------------------------------------
        |
        | The issuer name shown in the user's authenticator app next to the code.
        | When null it falls back to your application's name, config('app.name'),
        | which is the right value for most applications.
        |
        */

        'issuer' => env('LUKK_2FA_ISSUER'),

        /*
        |--------------------------------------------------------------------------
        | Verification Window
        |--------------------------------------------------------------------------
        |
        | How many 30-second steps of clock drift to accept on either side of the
        | current code. Keep this tight — widening it enlarges the window an
        | attacker can guess within, weakening the second factor.
        |
        */

        'window' => (int) env('LUKK_2FA_WINDOW', 1),

        /*
        |--------------------------------------------------------------------------
        | Recovery Codes
        |--------------------------------------------------------------------------
        |
        | How many single-use recovery codes to generate at enrolment. They are
        | shown once and stored hashed, for signing in when the authenticator
        | device is unavailable.
        |
        */

        'recovery_codes' => (int) env('LUKK_2FA_RECOVERY_CODES', 8),

        /*
        |--------------------------------------------------------------------------
        | Challenge Lifetime
        |--------------------------------------------------------------------------
        |
        | How long, in seconds, the short-lived challenge token returned at login
        | stays valid while the user fetches and submits their code.
        |
        */

        'challenge_ttl' => (int) env('LUKK_2FA_CHALLENGE_TTL', 300),
    ],

    /*
    |--------------------------------------------------------------------------
    | Step-Up Confirmation
    |--------------------------------------------------------------------------
    |
    | The "sudo" confirmation: a short-lived proof earned by re-entering a
    | password (or, with passkeys, a passkey assertion) that gates sensitive
    | routes via the 'lukk.confirm' middleware. Mirrors GitHub's sudo window.
    |
    */

    'confirm' => [

        /*
        |--------------------------------------------------------------------------
        | Confirmation Lifetime
        |--------------------------------------------------------------------------
        |
        | How long, in seconds, a confirmation stays valid once granted. Within
        | this window the user may act on gated routes without re-confirming.
        |
        */

        'ttl' => (int) env('LUKK_CONFIRM_TTL', 300),

        /*
        |--------------------------------------------------------------------------
        | Confirmation Header
        |--------------------------------------------------------------------------
        |
        | The request header the client presents the confirmation token in when
        | calling a route protected by the 'lukk.confirm' middleware.
        |
        */

        'header' => env('LUKK_CONFIRM_HEADER', 'X-Lukk-Confirmation'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Passkeys (WebAuthn / FIDO2)
    |--------------------------------------------------------------------------
    |
    | Passwordless credential settings. Requires the "passkeys" feature to be
    | enabled below and a WebAuthn library to be installed.
    |
    */

    'passkeys' => [

        /*
        |--------------------------------------------------------------------------
        | Relying Party Name
        |--------------------------------------------------------------------------
        |
        | The application name shown in the operating system's passkey prompt.
        | When null it falls back to your application's name, config('app.name').
        |
        */

        'rp_name' => env('LUKK_PASSKEY_RP_NAME'),

        /*
        |--------------------------------------------------------------------------
        | Relying Party ID
        |--------------------------------------------------------------------------
        |
        | The registrable domain shared by your front-end and API — for example
        | "example.com", NOT "api.example.com". Required when passkeys are
        | enabled (there is no safe automatic default).
        |
        */

        'rp_id' => env('LUKK_PASSKEY_RP_ID'),

        /*
        |--------------------------------------------------------------------------
        | Allowed Origins
        |--------------------------------------------------------------------------
        |
        | A comma-separated list of the browser origins (your front-end) allowed
        | to complete a passkey ceremony, for example "https://app.example.com".
        | Required when passkeys are enabled — an empty list is rejected.
        |
        */

        'origins' => array_values(array_filter(array_map('trim', explode(',', (string) env('LUKK_PASSKEY_ORIGINS', ''))))),

        /*
        |--------------------------------------------------------------------------
        | Challenge Lifetime
        |--------------------------------------------------------------------------
        |
        | How long, in seconds, a WebAuthn challenge stays valid while the user
        | completes the registration or login ceremony.
        |
        */

        'challenge_ttl' => (int) env('LUKK_PASSKEY_CHALLENGE_TTL', 120),

        /*
        |--------------------------------------------------------------------------
        | User Verification
        |--------------------------------------------------------------------------
        |
        | Whether the authenticator must verify the user (biometric / PIN) rather
        | than just their presence (a tap). Default "required" — passkey login and
        | step-up are single-factor (possession), so enforcing user verification
        | makes them phishing-resistant, AAL2-style. Lower to "preferred" only if
        | you must support authenticators that can't verify the user.
        | One of: "required", "preferred", "discouraged".
        |
        */

        'user_verification' => env('LUKK_PASSKEY_UV', 'required'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Denylist Cache Store
    |--------------------------------------------------------------------------
    |
    | The cache store backing the revocation denylist. Set to null to use the
    | application's default cache store.
    |
    */

    'denylist_store' => env('LUKK_DENYLIST_STORE'),

    /*
    |--------------------------------------------------------------------------
    | Cookie Mode
    |--------------------------------------------------------------------------
    |
    | When false (default, BFF), tokens are returned in the JSON body and the
    | Nuxt BFF seals them server-side. When true (direct browser client), the
    | refresh token is delivered in a __Host- prefixed cookie.
    |
    | "secure" gates the cookie's Secure attribute. Keep it true in production —
    | the refresh token must never travel over http. Set it false ONLY for local
    | development over plain http (a browser drops a Secure cookie on http, even on
    | localhost); lukk then also drops the __Host- prefix from the name, since that
    | prefix requires Secure. Never ship secure=false.
    |
    */

    'cookie_mode' => (bool) env('LUKK_COOKIE_MODE', false),

    'cookie' => [
        'refresh_name' => '__Host-refresh',
        'secure' => (bool) env('LUKK_COOKIE_SECURE', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication Guard & Provider
    |--------------------------------------------------------------------------
    |
    | The auth guard your application maps to the 'lukk-jwt' driver in
    | config/auth.php, and the user provider used to resolve and validate
    | credentials during login.
    |
    */

    'guard' => 'api',
    'user_provider' => 'users',

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    |
    | Whether to register the package's auth routes (login / refresh / logout /
    | logout-all) and the URI prefix they are mounted under.
    |
    */

    'routes' => true,
    'path' => 'auth',

    /*
    |--------------------------------------------------------------------------
    | Email Verification
    |--------------------------------------------------------------------------
    |
    | First-party email verification (opt-in via features.email_verification).
    | Your user model must implement Illuminate\Contracts\Auth\MustVerifyEmail
    | and the users table must have the framework-default `email_verified_at`
    | column — lukk ships no migration for it (it's a Laravel default).
    |
    */

    'email_verification' => [

        /*
        |--------------------------------------------------------------------------
        | Frontend URL
        |--------------------------------------------------------------------------
        |
        | Where the signed verification link ultimately lands the user (your SPA
        | verify page). The browser hits the API GET, which verifies then
        | redirects here (with ?verified=1); leave it empty to return 204 instead
        | of redirecting. An `Accept: application/json` fetch always gets 204.
        |
        */

        'frontend_url' => env('LUKK_VERIFY_URL'),

        /*
        |--------------------------------------------------------------------------
        | Link Lifetime
        |--------------------------------------------------------------------------
        |
        | The signed verification link's validity, in minutes.
        |
        */

        'expire' => (int) env('LUKK_VERIFY_EXPIRE', 60),

        /*
        |--------------------------------------------------------------------------
        | Block Unverified Login
        |--------------------------------------------------------------------------
        |
        | Refuse login with a 403 for an unverified user, instead of issuing
        | tokens and gating per-route with the `lukk.verified` middleware (409).
        | Default false — the SPA-friendly "log in, then gate the sensitive
        | routes" model.
        |
        */

        'block_unverified_login' => (bool) env('LUKK_VERIFY_BLOCK_LOGIN', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Password Reset
    |--------------------------------------------------------------------------
    |
    | First-party password reset (opt-in via features.password_reset), built on
    | Laravel's password broker. Your user model must implement
    | Illuminate\Contracts\Auth\CanResetPassword (the default `App\Models\User`
    | already does) and you need the framework-default `password_reset_tokens`
    | table + a configured `auth.passwords` broker — lukk ships no migration.
    | The token's lifetime + per-email throttle come from that broker
    | (`auth.passwords.users.expire` / `.throttle`).
    |
    */

    'password_reset' => [

        /*
        |--------------------------------------------------------------------------
        | Frontend URL
        |--------------------------------------------------------------------------
        |
        | Where the reset link lands the user (your SPA reset page). lukk points
        | Laravel's ResetPassword notification at it, appending `?token=...&email=...`;
        | that page collects the new password and POSTs it to `/auth/reset-password`.
        | Required when the feature is enabled — an empty value emails a link with
        | no host.
        |
        */

        'frontend_url' => env('LUKK_RESET_URL'),

        /*
        |--------------------------------------------------------------------------
        | Revoke Sessions on Reset
        |--------------------------------------------------------------------------
        |
        | When true (the default), a successful reset revokes every existing
        | session (refresh families + denylist), so a session that predates the
        | reset — e.g. an attacker's — can't survive it.
        |
        */

        'revoke_sessions' => (bool) env('LUKK_RESET_REVOKE_SESSIONS', true),

        /*
        |--------------------------------------------------------------------------
        | Broker
        |--------------------------------------------------------------------------
        |
        | The `auth.passwords` broker used to mint + verify reset tokens. Null uses
        | your app's default broker (config('auth.defaults.passwords')). Set this
        | only when you reset against a non-default broker — e.g. a separate admin
        | guard with its own token table.
        |
        */

        'broker' => env('LUKK_RESET_BROKER'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Feature Toggles
    |--------------------------------------------------------------------------
    |
    | Switches consumed by the Actions to enable or disable behavior. The core
    | features (rotation, reuse detection, denylist, logout-all) are on by
    | default; the two below are opt-in.
    |
    */

    'features' => [

        'rotation' => true,
        'reuse_detection' => true,
        'denylist' => true,
        'logout_all' => true,

        /*
        |--------------------------------------------------------------------------
        | Two-Factor Authentication
        |--------------------------------------------------------------------------
        |
        | Enable TOTP two-factor. Requires the published two-factor migration
        | (which adds columns to your users table) and pragmarx/google2fa.
        |
        */

        'two_factor' => false,

        /*
        |--------------------------------------------------------------------------
        | Passkeys
        |--------------------------------------------------------------------------
        |
        | Enable WebAuthn passkeys. Requires the published passkeys migration and
        | a WebAuthn library, e.g. web-auth/webauthn-lib.
        |
        */

        'passkeys' => false,

        /*
        |--------------------------------------------------------------------------
        | Email Verification
        |--------------------------------------------------------------------------
        |
        | Enable first-party email verification. Requires a user model that
        | implements MustVerifyEmail and the framework-default `email_verified_at`
        | column (no lukk migration). Configure it under `email_verification` above.
        |
        */

        'email_verification' => false,

        /*
        |--------------------------------------------------------------------------
        | Password Reset
        |--------------------------------------------------------------------------
        |
        | Enable first-party password reset (Laravel password broker). Requires a
        | user model that implements CanResetPassword, the framework-default
        | `password_reset_tokens` table, and an `auth.passwords` broker (no lukk
        | migration). Configure it under `password_reset` above.
        |
        */

        'password_reset' => false,
    ],

];
