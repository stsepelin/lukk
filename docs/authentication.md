# Authentication

- [Endpoints](#endpoints)
- [Logging In](#logging-in)
- [Refreshing Tokens](#refreshing-tokens)
- [Logging Out](#logging-out)
- [Output Modes](#output-modes)
- [Protecting Routes](#protecting-routes)
- [Starting Sessions Manually](#starting-sessions-manually)

<a name="endpoints"></a>
## Endpoints

When `lukk.routes` is `true` (the default), the package registers these routes under the `lukk.path` prefix (default `auth`):

| Method | Path | Middleware | Purpose |
|---|---|---|---|
| `POST` | `/auth/login` | login throttle | Exchange email + password for a token pair. |
| `POST` | `/auth/refresh` | `throttle:lukk-refresh` | Exchange a refresh token for a rotated pair. |
| `POST` | `/auth/logout` | `auth:api` | Revoke the current session. |
| `DELETE` | `/auth/sessions` | `auth:api` | Revoke every session for the user. |
| `DELETE` | `/auth/sessions/others` | `auth:api` | Revoke every session **except** the current one. |

> [!NOTE]
> The login throttle is the per-account failure limiter described in [Configuration → Rate Limits](configuration.md#rate-limits), not a route `throttle` middleware. All throttles — login, refresh, two-factor, passkeys — are tunable there.

<a name="logging-in"></a>
## Logging In

Post credentials to `/auth/login`:

```http
POST /auth/login
Content-Type: application/json

{ "email": "taylor@example.com", "password": "secret" }
```

On success you receive a token pair (the exact shape depends on the [output mode](#output-modes)):

```json
{
    "access_token": "eyJ0eXAiOiJhdCtqd3Qi...",
    "refresh_token": "9f8c1d...",
    "token_type": "Bearer",
    "expires_in": 900
}
```

Wrong credentials return `422`. Lukk's login is **constant-time**: an unknown email runs the same hashing work as a wrong password, so neither timing nor response shape reveals which accounts exist.

> [!NOTE]
> If the user has confirmed [two-factor authentication](two-factor-authentication.md) or you require [passkeys](passkeys.md), login returns a challenge instead of tokens. See those pages for the second step.

<a name="refreshing-tokens"></a>
## Refreshing Tokens

When the access token nears expiry, exchange the refresh token for a fresh pair:

```http
POST /auth/refresh
Content-Type: application/json

{ "refresh_token": "9f8c1d..." }
```

Each refresh **rotates** the token: the response contains a brand-new refresh token, and the old one is consumed. Replaying a consumed token after the grace window revokes the entire session — see [Reuse detection](architecture.md#reuse-detection).

The grace window (`grace_seconds`, default 30s) exists so concurrent refreshes don't fight. If the same token is presented twice within the window — multiple tabs, or SSR plus hydration — the second call gets a fresh **access** token under the same session, rather than being treated as theft.

> [!NOTE]
> In [cookie mode](#output-modes), the refresh token is read from the `__Host-refresh` cookie automatically, so the request body can be empty.

The full token lifecycle — a short-lived access token used until it nears expiry, then rotated via the long-lived refresh token:

```mermaid
sequenceDiagram
    participant App as App (client)
    participant API as lukk API

    App->>API: POST /auth/login { email, password }
    API-->>App: 200 { access_token (~15m), refresh_token (~30d) }
    App->>API: GET /protected · Authorization: Bearer access
    API-->>App: 200 (guard verifies sig/claims + denylist)
    Note over App: access token nears expiry
    App->>API: POST /auth/refresh { refresh_token }
    API-->>App: 200 { new access_token, new refresh_token } — rotated
    Note over API: old refresh token consumed;<br/>post-grace replay → whole family revoked
```

<a name="logging-out"></a>
## Logging Out

All logout routes require a valid access token (`auth:api`):

- **`POST /auth/logout`** revokes the current session and denylists its family, killing any access token issued for it within one request.
- **`DELETE /auth/sessions`** revokes every session belonging to the user — useful for a "log out everywhere" button.
- **`DELETE /auth/sessions/others`** revokes every session except the one making the request — useful after a password change.

<a name="output-modes"></a>
## Output Modes

The `lukk.cookie_mode` option controls where tokens are delivered. From a browser SPA or Nuxt app, the [lukk-js client](https://stsepelin.github.io/lukk-js/authentication) drives these endpoints for you; its two [transport modes](https://stsepelin.github.io/lukk-js/transport-modes) pair with the output modes below.

### BFF Mode (`cookie_mode => false`, default)

Both tokens are returned in the JSON body. This suits a server-side client — such as a Nuxt BFF — that seals the tokens server-side so the browser never sees them.

```json
{
    "access_token": "...",
    "refresh_token": "...",
    "token_type": "Bearer",
    "expires_in": 900
}
```

### Direct Browser Mode (`cookie_mode => true`)

The refresh token is set in a hardened `__Host-refresh` cookie (HttpOnly, Secure, `Path=/`, no `Domain`), and only the access token is in the body. This suits a browser client talking to the API directly, with no BFF in front of it.

```json
{
    "access_token": "...",
    "token_type": "Bearer",
    "expires_in": 900
}
```

<a name="protecting-routes"></a>
## Protecting Routes

Once the [guard is wired](installation.md#wiring-the-guard), protect routes with `auth:api` and resolve the user normally:

```php
Route::middleware('auth:api')->group(function () {
    Route::get('/me', fn (Request $request) => $request->user());
    Route::get('/projects', [ProjectController::class, 'index']);
});
```

On every request the guard verifies the JWT (pinning the algorithm and asserting `iss`/`aud`/`exp`/`nbf`), then checks the denylist by both `jti` and `fid`. A token that is expired, tampered, denylisted, or whose user has been deleted is rejected with `401`.

<a name="starting-sessions-manually"></a>
## Starting Sessions Manually

You don't have to use the built-in login endpoint. To issue tokens yourself — after a custom registration flow, an impersonation feature, or a social login — call `startSession()` on a user (provided by the [`HasRefreshTokens` trait](installation.md#preparing-the-user-model)):

```php
$pair = $user->startSession();

$pair->accessToken;   // the signed JWT
$pair->refreshToken;  // the opaque refresh token (shown once)
```

The returned `TokenPair` is a value object; the plaintext refresh token is available only here and is never retrievable again.

> [!NOTE]
> On the client, a custom registration form that hits your own route can bind Laravel validation with the [lukk-js form helper](https://stsepelin.github.io/lukk-js/forms).
