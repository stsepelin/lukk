# Introduction

- [Overview](#overview)
- [Why Lukk](#why-lukk)
- [The Token Model](#the-token-model)
- [Requirements](#requirements)

<a name="overview"></a>
## Overview

Lukk is a small, focused authentication package for **first-party** Laravel applications — applications where you own both the client and the API, so there is no third party to delegate to. It issues short-lived **access tokens** (signed JWTs) and long-lived, opaque, **rotating refresh tokens**, with reuse detection and instant revocation built in.

It is intentionally **not** Passport, Sanctum, or an OAuth2 server. There are no client IDs, redirect URIs, or authorization-code/PKCE flows — that machinery exists to delegate access to third parties, and a first-party app has none. Lukk keeps only the patterns that carry their weight:

- **Short-lived access JWTs** — stateless, verified on every request.
- **Opaque rotating refresh tokens** — rotated on every use, stored only as a hash.
- **Reuse detection** — replaying a consumed token revokes the entire session.
- **A denylist** — revoke an access token or a whole session instantly.

The package was built for a single-page application split across a front-end host (for example a Nuxt BFF at `app.example.com`) and a Laravel API (`api.example.com`), but it works for any first-party client.

> [!NOTE]
> A first-party JS/TS + Nuxt client, **[lukk-js](https://stsepelin.github.io/lukk-js/)**, is the companion package: it mirrors this HTTP contract in TypeScript and handles token attachment, refresh, and the 2FA/passkey ceremonies for a browser or Nuxt app.

> [!NOTE]
> The single runtime dependency is [`firebase/php-jwt`](https://github.com/firebase/php-jwt), the audited library that performs the JWS signing and verification. Everything else is Laravel core. Optional two-factor and passkey support each pull one additional library, but only when you enable the feature.

<a name="why-lukk"></a>
## Why Lukk

Lukk's architecture mirrors Laravel Sanctum, so it should feel familiar:

- A **contract per swappable piece**, each bound to a sensible default you can rebind.
- Single-purpose **Actions** that hold the policy.
- A static **`Lukk`** configuration hub with closure hooks.
- A dedicated request **guard** registered as the `lukk-jwt` driver.
- **Responsable** response contracts so you can reshape the output.

If you have used `Sanctum::usePersonalAccessTokenModel()`, you already know how to customize Lukk. See [Customization](customization.md).

<a name="the-token-model"></a>
## The Token Model

| | |
|---|---|
| **Access token** | An HS256 JWT, valid for 15 minutes. Carries the claims `iss`, `aud`, `sub`, `fid` (refresh family id), `jti`, `iat`, `nbf`, and `exp`, with the header `typ=at+jwt`. On every request the signing algorithm is pinned, `iss` and `aud` are asserted, and the denylist is checked by both `jti` and `fid`. |
| **Refresh token** | An opaque, 256-bit random string, valid for 30 days. Returned to the client once and stored only as a `sha256` hash. Rotated on every refresh; replaying one after the grace window revokes the whole token family. |

HS256 (a shared secret) is the correct choice while this application is the only thing that verifies its own tokens — there is no keypair to manage and no JWKS endpoint to publish. If an independent service ever needs to verify your tokens, RS256/ES256 + a JWKS endpoint + `kid` key rotation are built in (behind the same contracts): run `php artisan lukk:keygen`, flip `LUKK_ALGORITHM`, and it's a configuration change, not a rewrite. See [Architecture → Upgrading to RS256](architecture.md#upgrading-to-rs256).

<a name="requirements"></a>
## Requirements

- PHP `^8.3`
- Laravel `^12.0 | ^13.0`
- `firebase/php-jwt` `^7.0`

> [!WARNING]
> `firebase/php-jwt` v7 hard-enforces a HMAC secret of at least 256 bits. A too-short `LUKK_SECRET` fails loudly at signing time instead of weakly signing. The `php artisan lukk:secret` command (see [Installation](installation.md)) generates a key that clears this floor.
