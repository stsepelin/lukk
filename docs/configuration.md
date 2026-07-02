# Configuration

After publishing the config file with `php artisan vendor:publish --tag=lukk-config`, all options live in `config/lukk.php`. Every option has a default, and most are driven by environment variables so you can tune them per environment without editing the file.

- [Signing](#signing)
- [Issuer & Audience](#issuer-and-audience)
- [Token Lifetimes](#token-lifetimes)
- [Refresh Behavior](#refresh-behavior)
- [Rate Limits](#rate-limits)
- [Denylist](#denylist)
- [Output Mode](#output-mode)
- [Guard & Provider](#guard-and-provider)
- [Routes](#routes)
- [Feature Toggles](#feature-toggles)
- [Two-Factor](#two-factor)
- [Confirmation](#confirmation)
- [Passkeys](#passkeys)

<a name="signing"></a>
## Signing

```php
'algorithm' => env('LUKK_ALGORITHM', 'HS256'),
'secret' => env('LUKK_SECRET'),
```

| Key | Default | Description |
|---|---|---|
| `algorithm` | `HS256` | The JWS algorithm. Keep `HS256` while this app is the sole verifier of its own tokens; switch to `RS256`/`ES256` only when an independent service must verify them. |
| `secret` | `env('LUKK_SECRET')` | The 256-bit HS256 signing key. Generate it with [`php artisan lukk:secret`](installation.md#generating-the-signing-secret). Unused under an asymmetric algorithm. |

### Asymmetric keys (RS256 / ES256)

Used only when `algorithm` is asymmetric. Generate a keypair with `php artisan lukk:keygen` (add `--algorithm=ES256` for EC).

```php
'keys' => [
    'active' => env('LUKK_ACTIVE_KID', 'default'),
    'private' => env('LUKK_PRIVATE_KEY'),
    'passphrase' => env('LUKK_KEY_PASSPHRASE'),
    'public' => array_filter([
        env('LUKK_ACTIVE_KID', 'default') => env('LUKK_PUBLIC_KEY'),
    ]),
],
```

| Key | Description |
|---|---|
| `active` | The `kid` stamped on new tokens and used to select the signing key. |
| `private` | The signing key — an inline PEM or a path (`@/path` or a bare path). A verify-only service (the API side of a split) leaves this empty. |
| `passphrase` | Optional passphrase, if the private key is encrypted. |
| `public` | The `kid` → public-key map used to verify (and published at the [JWKS endpoint](#jwks-endpoint)). To **rotate** without forcing logouts: add the new key, point `active` at it, and keep the old key listed until its last token has expired. |

<a name="jwks-endpoint"></a>
### JWKS endpoint

Under an asymmetric algorithm, `GET {path}/jwks` publishes the public keys as a JWK Set (RFC 7517) — cacheable, exposing only public keys. Empty under `HS256`.

A lukk verifier reads keys from its own `keys.public` config, **not** by fetching this endpoint — so the endpoint exists to publish the keys to standards-based consumers (an API gateway, another framework), or as the canonical place to copy a key from into another lukk service's config.

<a name="issuer-and-audience"></a>
## Issuer & Audience

```dotenv
LUKK_ISSUER=https://api.example.com
LUKK_AUDIENCE=https://api.example.com
```

The `iss` and `aud` claims stamped into every token and validated on every request. Set both to your API's URL.

`LUKK_AUDIENCE` is **comma-separated**. To mint tokens for **several services**, list them all — `LUKK_AUDIENCE=https://api.example.com,https://billing.example.com`. The token then lists both, and each service accepts it when its own audience is in the list. A single audience is stamped as a plain string. See [Deployment](deployment.md).

<a name="token-lifetimes"></a>
## Token Lifetimes

```php
'access_ttl' => (int) env('LUKK_ACCESS_TTL', 900),       // 15 minutes
'refresh_ttl' => (int) env('LUKK_REFRESH_TTL', 2592000), // 30 days
```

| Key | Default | Description |
|---|---|---|
| `access_ttl` | `900` (15 min) | Access-token lifetime, in seconds. Keep it short — revocation latency is bounded by this value. |
| `refresh_ttl` | `2592000` (30 days) | The **absolute** session lifetime, in seconds. It is set at login and inherited by every rotation — it does **not** slide, so a session ends `refresh_ttl` after login regardless of activity, and the user must log in again. |

<a name="refresh-behavior"></a>
## Refresh Behavior

```php
'grace_seconds' => (int) env('LUKK_GRACE', 30),
'leeway' => (int) env('LUKK_LEEWAY', 5),
```

| Key | Default | Description |
|---|---|---|
| `grace_seconds` | `30` | The overlap window during which a just-rotated token is still tolerated, so concurrent refreshes (multiple tabs, SSR + hydration) do not trip reuse detection. Within this window the old token yields a fresh access token only — see [Authentication](authentication.md#refresh). |
| `leeway` | `5` | Clock-skew tolerance, in seconds, applied when validating the `exp` and `nbf` claims. |

<a name="rate-limits"></a>
## Rate Limits

Every throttle lives here, each shaped as `{ max_attempts, decay_seconds }` (login adds a third key, `ip_max_attempts`):

```php
'rate_limits' => [
    'login' => ['max_attempts' => 5, 'decay_seconds' => 60, 'ip_max_attempts' => 30],
    'two_factor' => ['max_attempts' => 5, 'decay_seconds' => 60],
    'refresh' => ['max_attempts' => 30, 'decay_seconds' => 60],
    'passkeys' => ['max_attempts' => 30, 'decay_seconds' => 60],
],
```

| Limit | Default | Keyed on | Notes |
|---|---|---|---|
| `login` | 5 / 60s (+ `ip_max_attempts` 30) | normalized email + IP | Failures-only: only failed attempts count, a success clears the counter; lockout returns a `429` validation error. **`ip_max_attempts`** (env `LUKK_LOGIN_IP_MAX_ATTEMPTS`) is a separate coarse per-IP cap on *all* login attempts, bounding password-spraying across many emails. |
| `two_factor` | 5 / 60s | account (`sub`) | Throttles challenge-code guesses for a single account. Also guards the endpoint per IP. |
| `refresh` | 30 / 60s | IP | Per-IP guard on `POST /auth/refresh`. |
| `passkeys` | 30 / 60s | IP | Per-IP guard on the passkey login + assertion-options endpoints. |

Each maps to a named limiter (`lukk-refresh`, `lukk-passkeys`, `lukk-2fa`) you can also override with your own `RateLimiter::for()`. Tune any of them with the matching env vars — `LUKK_REFRESH_MAX_ATTEMPTS`, `LUKK_2FA_DECAY`, and so on.

<a name="denylist"></a>
## Denylist

```php
'denylist_store' => env('LUKK_DENYLIST_STORE'),
```

The cache store backing the revocation denylist. `null` uses your application's default cache store. The denylist is self-evicting (entries expire with the tokens they revoke), so any cache driver works — Redis is recommended in production. Use a store that **throws** when unreachable (Redis, database): a denylist read error then propagates and access-token verification **fails closed** (rejects), rather than silently treating a revoked token as valid. Avoid a store that swallows connection errors into a `null`/miss.

> [!IMPORTANT]
> Across **multiple nodes** this must be a **shared, persistent** store (e.g. Redis) — not the `array` driver and not a per-node cache. The same store also backs the TOTP replay cache and the passkey/2FA throttles; if it isn't shared, a revoked token can still be honored on another node and replay protection isn't authoritative.

<a name="output-mode"></a>
## Output Mode

```php
'cookie_mode' => (bool) env('LUKK_COOKIE_MODE', false),

'cookie' => [
    'refresh_name' => '__Host-refresh',
    'secure' => (bool) env('LUKK_COOKIE_SECURE', true),
],
```

| Mode | Behavior |
|---|---|
| `false` (default) | **BFF mode.** Both tokens are returned in the JSON body, for a server-side client (such as a Nuxt BFF) that seals them itself. |
| `true` | **Direct browser mode.** The refresh token is set in a `__Host-refresh` cookie (HttpOnly, Secure, `Path=/`, no `Domain`); only the access token and its expiry are in the body. |

`cookie.secure` (env `LUKK_COOKIE_SECURE`, default `true`) controls the refresh cookie's
`Secure` attribute. **Keep it `true` in production** — the refresh token must never travel
over plain http. Set it to `false` **only for local development over http** (a browser drops
a `Secure` cookie on http, even on localhost, so the session wouldn't persist): lukk then also
strips the `__Host-` prefix from the cookie name, since that prefix requires `Secure`. Never
ship `secure=false`.

See [Authentication → Output Modes](authentication.md#output-modes) for the full response shapes, and the lukk-js [transport modes](https://stsepelin.github.io/lukk-js/transport-modes) for which client mode pairs with each (BFF ↔ body mode, direct ↔ cookie mode).

<a name="guard-and-provider"></a>
## Guard & Provider

```php
'guard' => 'api',
'user_provider' => 'users',
```

| Key | Default | Description |
|---|---|---|
| `guard` | `api` | The auth guard your app maps to the `lukk-jwt` driver. Used by the package's route middleware. |
| `user_provider` | `users` | The `config/auth.php` user provider used to resolve and validate credentials during login. |

<a name="routes"></a>
## Routes

```php
'routes' => true,
'path' => 'auth',
```

| Key | Default | Description |
|---|---|---|
| `routes` | `true` | Whether to register the package's built-in routes. Set to `false` to define your own. |
| `path` | `auth` | The URI prefix the routes are mounted under (e.g. `/auth/login`). |

<a name="feature-toggles"></a>
## Feature Toggles

```php
'features' => [
    'rotation' => true,
    'reuse_detection' => true,
    'denylist' => true,
    'logout_all' => true,
    'two_factor' => false,
    'passkeys' => false,
],
```

| Feature | Default | Description |
|---|---|---|
| `rotation` | `true` | Rotate the refresh token on every refresh. |
| `reuse_detection` | `true` | Revoke the whole family when a consumed token is replayed. |
| `denylist` | `true` | Honor the cache-backed revocation denylist. |
| `logout_all` | `true` | Enable the "revoke every session" path. |
| `two_factor` | `false` | Enable [two-factor authentication](two-factor-authentication.md). Requires `pragmarx/google2fa`. |
| `passkeys` | `false` | Enable [passkeys](passkeys.md). Requires a WebAuthn library. |

> [!WARNING]
> The rotation, reuse-detection, and denylist features are the security core of the package. Disable them only if you fully understand the consequence.

<a name="two-factor"></a>
## Two-Factor

Used only when `features.two_factor` is enabled. See [Two-Factor Authentication](two-factor-authentication.md).

```php
'two_factor' => [
    'issuer' => env('LUKK_2FA_ISSUER'),
    'window' => (int) env('LUKK_2FA_WINDOW', 1),
    'recovery_codes' => (int) env('LUKK_2FA_RECOVERY_CODES', 8),
    'challenge_ttl' => (int) env('LUKK_2FA_CHALLENGE_TTL', 300),
],
```

| Key | Default | Description |
|---|---|---|
| `issuer` | `config('app.name')` | The label shown in the authenticator app. |
| `window` | `1` | Accepted clock drift, in 30-second steps (±1). Do not widen this — it multiplies brute-force odds. |
| `recovery_codes` | `8` | How many recovery codes are generated. |
| `challenge_ttl` | `300` (5 min) | How long a login challenge token is valid. |

<a name="confirmation"></a>
## Confirmation

Settings for [step-up confirmation](confirmation.md).

```php
'confirm' => [
    'ttl' => (int) env('LUKK_CONFIRM_TTL', 300),
    'header' => env('LUKK_CONFIRM_HEADER', 'X-Lukk-Confirmation'),
],
```

| Key | Default | Description |
|---|---|---|
| `ttl` | `300` (5 min) | How long a confirmation ("sudo") proof remains valid. |
| `header` | `X-Lukk-Confirmation` | The request header that carries the confirmation token. |

<a name="passkeys"></a>
## Passkeys

Used only when `features.passkeys` is enabled. See [Passkeys](passkeys.md).

```php
'passkeys' => [
    'rp_name' => env('LUKK_PASSKEY_RP_NAME'),
    'rp_id' => env('LUKK_PASSKEY_RP_ID'),
    'origins' => array_values(array_filter(array_map('trim', explode(',', (string) env('LUKK_PASSKEY_ORIGINS', ''))))),
    'challenge_ttl' => (int) env('LUKK_PASSKEY_CHALLENGE_TTL', 120),
    'user_verification' => env('LUKK_PASSKEY_UV', 'required'),
],
```

| Key | Default | Description |
|---|---|---|
| `rp_name` | `config('app.name')` | The relying-party name shown in the OS passkey prompt. |
| `rp_id` | **required** | The registrable domain shared by your front-end and API — e.g. `example.com`, **not** `api.example.com`. Throws if unset when passkeys are enabled. |
| `origins` | **required** | Allowed browser origins (your front-end), as a comma-separated `LUKK_PASSKEY_ORIGINS` value. An empty list is rejected. |
| `challenge_ttl` | `120` (2 min) | How long a WebAuthn challenge is valid. |
| `user_verification` | `required` | Whether the authenticator must verify the user (biometric/PIN), not just their presence. Default `required` makes passwordless login + step-up phishing-resistant (AAL2). Lower to `preferred` only for authenticators that can't verify the user. One of `required`, `preferred`, `discouraged`. |
