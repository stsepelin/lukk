# Installation

- [Requirements](#requirements)
- [Installing the Package](#installing-the-package)
- [Generating the Signing Secret](#generating-the-signing-secret)
- [Configuring the Environment](#configuring-the-environment)
- [Wiring the Guard](#wiring-the-guard)
- [Preparing the User Model](#preparing-the-user-model)

<a name="requirements"></a>
## Requirements

- PHP `^8.3`
- Laravel `^12.0 | ^13.0`

<a name="installing-the-package"></a>
## Installing the Package

Install the package with Composer:

```bash
composer require lukk/lukk
```

Publish the configuration file and the core migration, then run it:

```bash
php artisan vendor:publish --tag=lukk-config       # config/lukk.php
php artisan vendor:publish --tag=lukk-migrations   # refresh_tokens migration
php artisan migrate
```

> [!NOTE]
> Lukk's migrations are **publish-only** — nothing runs until you publish it — following the same convention as Sanctum and Passport. Each optional feature ([two-factor](two-factor-authentication.md), [passkeys](passkeys.md)) is its own publish group, so you only add its schema when you enable that feature.

<a name="generating-the-signing-secret"></a>
## Generating the Signing Secret

Access tokens are signed with a 256-bit secret. Generate one and write it to your `.env` file with the `lukk:secret` command:

```bash
php artisan lukk:secret
```

The command behaves like Laravel's `key:generate`:

| Option | Effect |
|---|---|
| _(none)_ | Generates a new secret and writes `LUKK_SECRET` to `.env`. Prompts before overwriting an existing one. |
| `--force` | Overwrites an existing secret without prompting. |
| `--show` | Prints the generated secret instead of writing it. |

> [!WARNING]
> Treat `LUKK_SECRET` like `APP_KEY`. It is never committed to source control, and rotating it invalidates every access token signed with the old value (refresh tokens are opaque and unaffected, so clients can recover on their next refresh).

> [!NOTE]
> Running a **split** auth-service / verify-only-API topology? Use asymmetric signing instead — `php artisan lukk:keygen` and `LUKK_ALGORITHM=RS256`. See [Configuration → Asymmetric keys](configuration.md#asymmetric-keys-rs256--es256).

<a name="configuring-the-environment"></a>
## Configuring the Environment

Set the issuer and audience to your API's URL. They are stamped into every token and validated on every request:

```dotenv
LUKK_ISSUER=https://api.example.com
LUKK_AUDIENCE=https://api.example.com
```

Every other setting has a sensible default. See [Configuration](configuration.md) for the full list.

<a name="wiring-the-guard"></a>
## Wiring the Guard

Lukk registers a `lukk-jwt` auth driver. Map a guard to it in `config/auth.php`:

```php
'guards' => [
    'api' => [
        'driver' => 'lukk-jwt',
        'provider' => 'users',
    ],
],
```

You can now protect routes with the `auth:api` middleware exactly as you would any other guard:

```php
use Illuminate\Http\Request;

Route::middleware('auth:api')->get('/me', fn (Request $request) => $request->user());
```

> [!IMPORTANT]
> **Render API errors as JSON.** Laravel's `php artisan install:api` configures JSON error responses only for the `api/*` path. Lukk's routes are mounted at `/auth/*` (default), so for a missing token or failed validation to return a JSON `401`/`422` instead of a web redirect, extend that rule in `bootstrap/app.php` (or mount your protected routes under `api/`):
>
> ```php
> ->withExceptions(function (Illuminate\Foundation\Configuration\Exceptions $exceptions) {
>     $exceptions->shouldRenderJsonWhen(
>         fn ($request) => $request->is('auth/*') || $request->expectsJson(),
>     );
> })
> ```
>
> (The refresh endpoint already returns a self-rendered `401` regardless of this setting.)

<a name="preparing-the-user-model"></a>
## Preparing the User Model

Adding the `HasRefreshTokens` trait to your `User` model is optional but ergonomic. It exposes helpers for managing a user's sessions:

```php
use Illuminate\Foundation\Auth\User as Authenticatable;
use Lukk\Concerns\HasRefreshTokens;

class User extends Authenticatable
{
    use HasRefreshTokens;
}
```

The trait adds three methods:

| Method | Description |
|---|---|
| `$user->refreshTokens()` | The `HasMany` relationship to the user's refresh tokens. |
| `$user->startSession()` | Starts a new session and returns a `TokenPair` (access + refresh token). |
| `$user->revokeAllSessions()` | Revokes every session belonging to the user. |

That's it — you're ready to authenticate. Head to [Authentication](authentication.md).
