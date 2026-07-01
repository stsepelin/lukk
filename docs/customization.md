# Customization

Lukk follows the Sanctum pattern: every moving part is either a **contract bound to a default** (rebind it in a service provider) or a **closure hook** on the static `Lukk` class (register it from a service provider's `boot` method). You never edit the package.

- [The Lukk Hub](#the-lukk-hub)
- [Custom Login Logic](#custom-login-logic)
- [Custom Token Claims](#custom-token-claims)
- [Swapping the Refresh Token Model](#swapping-the-refresh-token-model)
- [Swapping Storage](#swapping-storage)
- [Reshaping Responses](#reshaping-responses)
- [Swapping the Issuer, Verifier, or Denylist](#swapping-the-issuer-verifier-or-denylist)
- [Available Contracts](#available-contracts)

<a name="the-lukk-hub"></a>
## The Lukk Hub

The `Lukk` class is a static configuration hub, like `Sanctum`. Register hooks from the `boot` method of a service provider (for example `App\Providers\AppServiceProvider`):

```php
use Lukk\Lukk;

public function boot(): void
{
    Lukk::authenticateUsing(/* ... */);
    Lukk::tokenClaimsUsing(/* ... */);
    Lukk::useRefreshTokenModel(/* ... */);
}
```

<a name="custom-login-logic"></a>
## Custom Login Logic

By default Lukk validates the `email` and `password` against your configured user provider. To take full control — extra conditions, a different credential field, a "must be active" check — pass a closure to `authenticateUsing`. Return the authenticated user, or `null` to reject:

```php
use Illuminate\Http\Request;
use Lukk\Lukk;

Lukk::authenticateUsing(function (Request $request) {
    $user = User::where('email', $request->input('email'))->first();

    if ($user && Hash::check($request->input('password'), $user->password) && $user->is_active) {
        return $user;
    }

    return null;
});
```

The login **throttle** still wraps your closure — failed attempts are rate-limited exactly as on the default path. **Constant-time** behaviour, however, becomes *your* responsibility: the package's unknown-user timing equalizer only runs on the built-in email/password path, so a closure that does `User::where(...)->first()` and hashes only when the user exists leaks a user-enumeration timing oracle. Make your closure take the same time whether or not the account exists — e.g. always run a `Hash::check` against a dummy hash when no user is found.

<a name="custom-token-claims"></a>
## Custom Token Claims

Add custom claims — roles, a tenant id, anything your API needs — to every access token. The closure receives the user id and returns an array of claims:

```php
use Lukk\Lukk;

Lukk::tokenClaimsUsing(fn ($userId) => [
    'roles' => User::find($userId)->roles->pluck('name'),
]);
```

> [!NOTE]
> Your claims are merged in, but the standard claims (`sub`, `exp`, `iss`, `aud`, `jti`, `fid`, …) always win and cannot be overridden.

<a name="swapping-the-refresh-token-model"></a>
## Swapping the Refresh Token Model

To use your own Eloquent model for refresh tokens (to add columns, relationships, or scopes), extend the base model and register it — the Sanctum approach:

```php
use Lukk\Lukk;
use App\Models\RefreshToken;

Lukk::useRefreshTokenModel(RefreshToken::class);
```

<a name="swapping-storage"></a>
## Swapping Storage

Refresh-token **storage** sits behind `Contracts\RefreshTokenRepository`, separate from the rotation **policy** (which lives in `Actions\RotateRefreshToken`). To move storage from the database to Redis, bind your own implementation — the policy is untouched:

```php
use Lukk\Contracts\RefreshTokenRepository;
use App\Auth\RedisRefreshTokenRepository;

$this->app->bind(RefreshTokenRepository::class, RedisRefreshTokenRepository::class);
```

<a name="reshaping-responses"></a>
## Reshaping Responses

The login, refresh, and logout responses are `Responsable` contracts. Rebind one to change the body shape, add headers, or switch between JSON and cookies:

```php
use Lukk\Contracts\LoginResponse;
use App\Http\Responses\MyLoginResponse;

$this->app->bind(LoginResponse::class, MyLoginResponse::class);
```

The response contracts are `LoginResponse`, `RefreshResponse`, `LogoutResponse`, and `TwoFactorChallengeResponse`.

> [!NOTE]
> The default response shape is the contract the [lukk-js clients](https://stsepelin.github.io/lukk-js/) consume. If you reshape it, keep the client in sync (or adapt it) so the two don't drift.

<a name="swapping-the-issuer-verifier-or-denylist"></a>
## Swapping the Issuer, Verifier, or Denylist

The cryptographic and revocation seams are contracts too. Rebind `Contracts\TokenIssuer` or `Contracts\TokenVerifier` to change how tokens are minted or validated (for example to move to RS256), or `Contracts\Denylist` to back revocation with something other than the cache.

<a name="available-contracts"></a>
## Available Contracts

| Contract | Default | Responsibility |
|---|---|---|
| `TokenIssuer` | `FirebaseTokenIssuer` | Mints access tokens. |
| `TokenVerifier` | `FirebaseTokenVerifier` | Verifies access tokens and checks the denylist. |
| `RefreshTokenRepository` | `DatabaseRefreshTokenRepository` | Persists refresh tokens and families. |
| `Denylist` | `CacheDenylist` | Records and checks revoked `jti`/`fid` values. |
| `LoginResponse` / `RefreshResponse` / `LogoutResponse` | built-in | Shape the HTTP responses. |
| `TwoFactorChallengeResponse` | built-in | Shapes the 2FA login challenge. |
| `TwoFactorProvider` | `Google2FaTotpProvider` | Generates and verifies TOTP codes. |
| `WebAuthnCeremony` | `SpomkyWebAuthnCeremony` | Performs WebAuthn registration/assertion. |
| `PasskeyRepository` | `DatabasePasskeyRepository` | Persists passkey credentials. |
