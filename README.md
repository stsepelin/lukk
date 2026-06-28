# lukk

[![Latest Version](https://img.shields.io/packagist/v/lukk/lukk.svg?style=flat-square)](https://packagist.org/packages/lukk/lukk)
[![Tests](https://img.shields.io/github/actions/workflow/status/stsepelin/lukk/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/stsepelin/lukk/actions/workflows/tests.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg?style=flat-square)](https://github.com/stsepelin/lukk/actions/workflows/tests.yml)
[![PHP Version](https://img.shields.io/packagist/php-v/lukk/lukk.svg?style=flat-square)](https://packagist.org/packages/lukk/lukk)
[![License](https://img.shields.io/packagist/l/lukk/lukk.svg?style=flat-square)](LICENSE.md)
[![Total Downloads](https://img.shields.io/packagist/dt/lukk/lukk.svg?style=flat-square)](https://packagist.org/packages/lukk/lukk)

Minimal-dependency JWT authentication for **first-party Laravel apps** (Laravel 12/13) — "first-party" meaning *you own both the client and the API*, so there's no third party to delegate to and no OAuth ceremony to perform.

> **Unofficial, independent package.** Not affiliated with, endorsed by, or maintained by the Laravel team. "Laravel", "Sanctum", and "Fortify" are referenced only to describe compatibility and design influence; they are trademarks of their respective owners.

## Features

- **Short-lived access JWTs** (HS256, 15 min) — stateless, verified on every request with the algorithm pinned and `iss`/`aud` asserted.
- **Opaque rotating refresh tokens** (30 days) — stored only as a `sha256` hash, rotated on every use.
- **Reuse detection** — replaying a consumed token revokes the whole session (token family).
- **Concurrency grace window** — multiple tabs / SSR refresh without false logouts.
- **Instant revocation** — a cache-backed denylist kills an access token or a whole session within one request.
- **Optional [two-factor auth](docs/two-factor-authentication.md)** (TOTP + recovery codes) and **[passkeys](docs/passkeys.md)** (WebAuthn / FIDO2), each opt-in and feature-gated.
- **Sanctum/Fortify-style design** — a contract per swappable piece, single-purpose Actions, a static `Lukk` config hub, a dedicated guard, and Responsable response contracts.

The single runtime dependency is [`firebase/php-jwt`](https://github.com/firebase/php-jwt), the audited JWS primitive — never hand-roll JWT. Everything else is Laravel core.

## Token model

| | |
|---|---|
| **Access token** | HS256 JWT, 15 min. Claims `iss/aud/sub/fid/jti/iat/nbf/exp`, header `typ=at+jwt`. Verified every request: alg pinned, `iss`/`aud` asserted, denylist checked by `jti` and `fid`. |
| **Refresh token** | Opaque 256-bit secret, 30 days. Returned once; stored only as `sha256`. Rotated on every refresh; reuse after the grace window revokes the whole family. |

HS256 is correct while this app is its own sole verifier. RS256/ES256 + a JWKS endpoint + `kid` key rotation are built in (behind the same contracts) for when an independent service must verify tokens — flip `LUKK_ALGORITHM` and run `php artisan lukk:keygen`. See [Architecture & Security](docs/architecture.md).

## Requirements

- PHP `^8.3`
- Laravel `^12.0 | ^13.0`
- `firebase/php-jwt` `^7.0`

## Quick start

```bash
composer require lukk/lukk

php artisan vendor:publish --tag=lukk-config       # config/lukk.php
php artisan vendor:publish --tag=lukk-migrations   # refresh_tokens migration
php artisan migrate
php artisan lukk:secret                            # writes LUKK_SECRET to .env
```

Map a guard to the `lukk-jwt` driver in `config/auth.php`:

```php
'guards' => [
    'api' => ['driver' => 'lukk-jwt', 'provider' => 'users'],
],
```

Then protect routes with `auth:api` as usual:

```php
Route::middleware('auth:api')->get('/me', fn (Request $r) => $r->user());
```

The package registers `login`, `refresh`, `logout`, and session-revocation (`DELETE /sessions`, `DELETE /sessions/others`) routes automatically. See **[Installation](docs/installation.md)** and **[Authentication](docs/authentication.md)** for the full walkthrough.

## Documentation

Full documentation lives in [`docs/`](docs/README.md):

| | |
|---|---|
| [Introduction](docs/introduction.md) | What Lukk is, the token model, and when to use it |
| [Installation](docs/installation.md) | Install, generate the secret, wire the guard |
| [Configuration](docs/configuration.md) | Every option, explained |
| [Authentication](docs/authentication.md) | Login, refresh, logout, protecting routes, output modes |
| [Customization](docs/customization.md) | Swap login logic, storage, models, responses, claims |
| [Events & Maintenance](docs/events.md) | Security events, token pruning, testing |
| [Two-Factor Authentication](docs/two-factor-authentication.md) | TOTP with recovery codes |
| [Passkeys](docs/passkeys.md) | Passwordless, phishing-resistant WebAuthn login |
| [Confirmation](docs/confirmation.md) | Step-up ("sudo") confirmation for sensitive routes |
| [Deployment](docs/deployment.md) | Single service, splitting auth from the API, multiple audiences |
| [Architecture & Security](docs/architecture.md) | Design rationale, standards mapping, security checklist |

## Testing

```bash
composer install
vendor/bin/pest
```

## License

MIT.
