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
    | Family Fork Threshold
    |--------------------------------------------------------------------------
    |
    | Live, unrotated tokens one family may hold before Events\RefreshFamilyForked
    | fires. The grace window above mints a sibling for a concurrent refresh, so a
    | family legitimately carries two or three; a family forked by a thief racing
    | inside the window keeps growing. Advisory only — lukk never revokes on it,
    | because revoking on suspicion is the false logout the grace window exists to
    | prevent. Minimum 2.
    |
    */

    'fork_threshold' => (int) env('LUKK_FORK_THRESHOLD', 3),

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
    | Every throttle below is keyed on the caller's IP, with IPv6 collapsed to
    | its /64 (one subscriber is typically handed a whole /64, so keying on the
    | full address would let a single visitor mint unlimited buckets). Behind a
    | BFF or reverse proxy that address is the PROXY until the deployment
    | forwards the real client — see the deployment docs. Replace the identity
    | entirely with Lukk::rateLimitKeyUsing() if the source address is not the
    | right bucket for you.
    |
    | The authenticated email-verification resend carries a second, per-user
    | limit as well, because rotating IPs is cheap once the per-IP limit is
    | genuinely per-visitor.
    |
    | "ipv6_prefix" is the mask applied to an IPv6 caller. 64 suits residential
    | and mobile networks, where a subscriber holds a whole /64. Lower it (56,
    | 48) if your attackers hold larger delegations; raise it (128 = per address)
    | if your users share a /64 — an office or campus LAN does.
    |
    */

    /*
    |--------------------------------------------------------------------------
    | Account Lockout
    |--------------------------------------------------------------------------
    |
    | Only used when features.lockout is on. "max_attempts" is the consecutive
    | failure cap — NIST SP 800-63B §5.2.2 says no more than 100, so treat that
    | as a ceiling, not a target. The counter is cleared by any successful
    | authentication, never by time.
    |
    | "release_after" auto-lifts a lock that many seconds after it was set; 0
    | holds it until a password reset, `php artisan lukk:release`, or your own
    | code clears it.
    |
    | The two settings pull against each other, so choose deliberately. 0 is the
    | strict §5.2.2 reading — a run broken only by a SUCCESS — but it means an
    | attacker who locks an account has denied it until someone intervenes.
    | Setting it trades that for a decaying cap: 100 / 3600 is no longer "100
    | consecutive, ever", it is 100 per hour, which is exactly OWASP ASVS V2.2.1
    | ("no more than 100 failed attempts per hour on a single account") and which
    | this package does NOT otherwise meet (the per-account throttle allows
    | ~1,200/hour). Most deployments should prefer that trade.
    |
    */

    'lockout' => [
        'max_attempts' => (int) env('LUKK_LOCKOUT_MAX_ATTEMPTS', 100),
        'release_after' => (int) env('LUKK_LOCKOUT_RELEASE_AFTER', 0),
    ],

    'rate_limits' => [

        'ipv6_prefix' => (int) env('LUKK_RATE_LIMIT_IPV6_PREFIX', 64),

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
        | Step-Up Confirmation
        |--------------------------------------------------------------------------
        |
        | Guards `POST /auth/confirm-password` and `/auth/confirm-passkey`. These
        | are authenticated, so the meaningful bucket is the USER, not the address:
        | a caller holding a stolen access token is one identity behind however
        | many IPs they like. Both a per-user and a per-IP limit are applied, and
        | the tighter wins.
        |
        | Without this the sudo re-auth was an unmetered password oracle for anyone
        | already holding a token — the same secret the login route throttles twice
        | over. Keep it tight; a legitimate user confirms a handful of times a day.
        |
        */

        'confirm' => [
            'max_attempts' => (int) env('LUKK_CONFIRM_MAX_ATTEMPTS', 5),
            'decay_seconds' => (int) env('LUKK_CONFIRM_DECAY', 60),
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

        /*
        |--------------------------------------------------------------------------
        | Registration
        |--------------------------------------------------------------------------
        |
        | A per-IP guard on the register endpoint.
        |
        */

        'registration' => [
            'max_attempts' => (int) env('LUKK_REGISTER_MAX_ATTEMPTS', 10),
            'decay_seconds' => (int) env('LUKK_REGISTER_DECAY', 60),
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
    | Login Identifier
    |--------------------------------------------------------------------------
    |
    | The users-table column that identifies an account at login and registration
    | (Fortify-style). Defaults to "email" (validated as an email address); set it
    | to "username" — or any unique column — to authenticate by that instead. Login
    | reads this field from the request, throttles per this identifier, and looks
    | the user up by it; registration validates + writes it.
    |
    */

    'username' => env('LUKK_USERNAME', 'email'),

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    |
    | Whether to register the package's auth routes (login / refresh / logout /
    | logout-all), the URI prefix they mount under, and an optional host. Leave
    | "domain" null to serve on any host, or set it (e.g. "api.example.com") to
    | bind the routes to a subdomain — the stronger isolation for multi-guard.
    |
    */

    'routes' => true,
    'path' => 'auth',
    'domain' => env('LUKK_DOMAIN'),

    /*
    |--------------------------------------------------------------------------
    | Guards (multi-audience isolation)
    |--------------------------------------------------------------------------
    |
    | lukk is single-guard by default: everything above is the DEFAULT guard
    | (config('lukk.guard')). To serve a second isolated audience — an admin API
    | alongside the users API — declare it here AND as a `lukk-jwt` guard in
    | config/auth.php (whose `provider` lukk reuses). Each entry deep-merges over
    | the top-level config, overriding only what differs:
    |
    |   'guards' => [
    |       'admin' => [
    |           'audience' => env('LUKK_ADMIN_AUDIENCE'),  // REQUIRED, distinct — the isolation
    |           'secret'   => env('LUKK_ADMIN_SECRET'),    // optional: a separate signing key
    |           'issuer'   => env('LUKK_ADMIN_ISSUER'),
    |           'path'     => 'auth',                       // route prefix (with domain below)
    |           'domain'   => 'admin.api.example.com',      // optional subdomain
    |       ],
    |   ],
    |
    | A token minted for one guard is rejected by another on the audience check
    | (+ signature when keys differ). Each guard MUST declare a distinct, non-empty
    | audience and mount at a distinct path/domain — lukk refuses to boot otherwise.
    | Leave empty for a single-guard app (zero behavioral change).
    |
    */

    'guards' => [],

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
    | Registration
    |--------------------------------------------------------------------------
    |
    | First-party registration (opt-in via features.registration). The built-in
    | default creates the configured model with name + email + a hashed password
    | (the stock Laravel `users` shape). Own the fields entirely with
    | Lukk::registerUsing() / Lukk::registerValidation() when your schema differs.
    |
    */

    'registration' => [

        /*
        |--------------------------------------------------------------------------
        | Auto-Login
        |--------------------------------------------------------------------------
        |
        | After creating the account, issue a session (a token pair) just like login
        | (true, the default) — or create the account only and return a 201 so the
        | user signs in separately (false).
        |
        */

        'login' => (bool) env('LUKK_REGISTER_LOGIN', true),
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
        | Account Lockout
        |--------------------------------------------------------------------------
        |
        | NIST SP 800-63B §5.2.2 requires a verifier to limit CONSECUTIVE failed
        | authentication attempts on one account to no more than 100. The throttles
        | above are decaying windows — they bound a rate, not a run — so satisfying
        | the clause needs a persistent counter. Requires the published lockout
        | migration.
        |
        | Off by default because a hard lockout is a denial-of-service primitive:
        | anyone who knows an address can burn its budget deliberately. Turn it on
        | when the protocol requirement outweighs that, and set "release_after" so
        | the denial is bounded.
        |
        | RETENTION: a counter row is created for every failed identifier, existing or
        | not — including addresses that name no account, which is deliberate (a
        | lock that only existed for real accounts would answer "does this account
        | exist?"). The table therefore accumulates plaintext identifiers an attacker
        | probed, third parties' addresses among them. "lukk:prune" drops spent rows
        | (--lockout-days, default 30); if that retention doesn't suit your privacy
        | posture, shorten it or swap LockoutRepository for one that stores an HMAC
        | of the subject.
        |
        | The counter keys on the "username" field above. If you use
        | Lukk::authenticateUsing() to authenticate on a DIFFERENT field, set
        | "username" to match it — otherwise lukk never sees an identifier to count
        | against, and the lockout does nothing (it refuses to count an empty
        | subject rather than put every caller in one shared, never-decaying
        | bucket).
        |
        */

        'lockout' => false,

        /*
        |--------------------------------------------------------------------------
        | Change Password
        |--------------------------------------------------------------------------
        |
        | An authenticated POST /auth/password: re-verify the current password, set
        | a new one, revoke every OTHER session, fire PasswordChanged. No email
        | round-trip — the caller already holds a session and can prove the
        | existing password.
        |
        | On by default, like "logout_all": it needs no configuration, and refusing
        | a signed-in user the ability to change their own password is not a
        | sensible default. Turn it off where passwords live somewhere else (SSO,
        | an identity provider, your own endpoint).
        |
        */

        'change_password' => (bool) env('LUKK_CHANGE_PASSWORD', true),

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

        /*
        |--------------------------------------------------------------------------
        | Registration
        |--------------------------------------------------------------------------
        |
        | Enable the first-party `POST {prefix}/register` endpoint. The default create
        | works with the stock Laravel `users` shape out of the box (name + the identifier
        | + a hashed password); own the fields entirely via `Lukk::registerUsing()` /
        | `Lukk::registerValidation()` (or by rebinding RegisterRequest) when your schema
        | differs. For public forms, add a captcha via `registerValidation`. Off by default.
        |
        */

        'registration' => false,
    ],

];
