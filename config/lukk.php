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
    |  - "login" is the failures-only limiter: only failed attempts count, a
    |    success clears the counter, keyed on the normalized email + IP.
    |    "ip_max_attempts" is a separate coarse per-IP cap on ALL login requests,
    |    so password spraying (varying the email) can't slip past the per-account
    |    limit.
    |  - "two_factor" values feed two limiters: a per-IP cap on the challenge
    |    route, and the real per-account guess limit (keyed by "sub") enforced
    |    inside the verify action.
    |  - "refresh" and "passkeys" are per-IP guards on those endpoints.
    |
    */

    'rate_limits' => [
        'login' => [
            'max_attempts' => (int) env('LUKK_LOGIN_MAX_ATTEMPTS', 5),
            'decay_seconds' => (int) env('LUKK_LOGIN_DECAY', 60),
            'ip_max_attempts' => (int) env('LUKK_LOGIN_IP_MAX_ATTEMPTS', 30),
        ],
        'two_factor' => [
            'max_attempts' => (int) env('LUKK_2FA_MAX_ATTEMPTS', 5),
            'decay_seconds' => (int) env('LUKK_2FA_DECAY', 60),
        ],
        'refresh' => [
            'max_attempts' => (int) env('LUKK_REFRESH_MAX_ATTEMPTS', 30),
            'decay_seconds' => (int) env('LUKK_REFRESH_DECAY', 60),
        ],
        'passkeys' => [
            'max_attempts' => (int) env('LUKK_PASSKEY_MAX_ATTEMPTS', 30),
            'decay_seconds' => (int) env('LUKK_PASSKEY_DECAY', 60),
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
        | than just their presence (a tap). "preferred" (default) accepts either;
        | set "required" for phishing-resistant, AAL2-style login and step-up.
        | One of: "required", "preferred", "discouraged".
        |
        */

        'user_verification' => env('LUKK_PASSKEY_UV', 'preferred'),
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
    */

    'cookie_mode' => (bool) env('LUKK_COOKIE_MODE', false),

    'cookie' => [
        'refresh_name' => '__Host-refresh',
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
    ],

];
