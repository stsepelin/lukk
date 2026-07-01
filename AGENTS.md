# AGENTS.md

Guidance for AI coding assistants. Two audiences: teams **using** lukk in a Laravel app, and contributors **working on** this repo.

Docs: <https://stsepelin.github.io/lukk/> — machine-readable at [`/llms.txt`](https://stsepelin.github.io/lukk/llms.txt) and [`/llms-full.txt`](https://stsepelin.github.io/lukk/llms-full.txt). First-party JS/TS + Nuxt client: [lukk-js](https://stsepelin.github.io/lukk-js/).

## Using lukk in a Laravel app

lukk is minimal-dependency JWT auth for **first-party** apps (you own the client and the API): short-lived HS256 access JWTs + opaque rotating refresh tokens with reuse detection, a concurrency grace window, and a cache-backed denylist. It is intentionally **not** Passport/Sanctum/OAuth — no authorization-code/PKCE ceremony.

**Setup:** install via Composer; `php artisan lukk:secret` (a short secret throws — `firebase/php-jwt ^7` enforces ≥ 256-bit); migrations are **publish-only** (Sanctum convention — publish the group, then migrate); wire the `auth:api` guard on protected routes; add the `HasRefreshTokens` trait to your User model.

**Output modes** (`lukk.cookie_mode`): `false` (default, "BFF" — both tokens in the JSON body, for a server-side client that seals them) vs `true` ("direct browser" — refresh token in a `__Host-refresh` cookie, access token in the body). Pair this with the client's transport mode.

**Customize via the Sanctum-style seams — never edit the package:**
- `Lukk::authenticateUsing(fn (Request $r) => $user|null)` — custom or replaced credential fields (username/phone), extra validation, custom login logic. The login throttle still wraps it; **constant-time behaviour becomes yours** on this path.
- `Lukk::tokenClaimsUsing(fn ($userId) => [...])` — add claims (roles, tenant). Standard claims (`sub`/`exp`/`iss`/`aud`/`jti`/`fid`) always win.
- Rebind the response contracts (`LoginResponse`, `RefreshResponse`, `LogoutResponse`, `TwoFactorChallengeResponse`) to reshape bodies — but the default shape is what [lukk-js clients](https://stsepelin.github.io/lukk-js/) consume, so keep them in sync.
- `Lukk::useRefreshTokenModel(...)`, and contract rebinds for storage / issuer / verifier / denylist.

**Registration is app-owned** — lukk has no register endpoint. Create the user yourself, then `$user->startSession()` returns a `TokenPair` (the plaintext refresh token is shown once).

**Operational must-dos:**
- Keep `grace_seconds > 0` (default 30s) — a zero grace window turns any concurrent refresh into a full-family revocation.
- Behind a BFF, every user's auth traffic egresses one IP: raise the per-IP login/refresh throttles and forward `X-Forwarded-For`.
- Passkeys: set `rp_id`/`origins` to the **browser-facing** origin (your app), never the API host.

## Contributing to this repo

See **[`CLAUDE.md`](./CLAUDE.md)** for the full contributor guide and the security invariants that must not break. In short: **one runtime dependency** (`firebase/php-jwt`); always alg-pin (never read the alg from the token header); refresh tokens are opaque, stored only as `sha256`, never logged; rotation + reuse detection are the point (TDD the rotate policy — a false-positive family revoke is a release blocker); login stays constant-time; the pest suite is 100%-covered (`vendor/bin/pest`), lint with `vendor/bin/pint`. Run a code review and a security review before committing, and never commit without explicit approval.
