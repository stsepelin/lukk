# CLAUDE.md — `lukk`

Minimal-dependency, first-party JWT auth package for Laravel 12/13 (`Lukk\` namespace): short-lived HS256 access JWTs + opaque rotating refresh tokens with reuse detection, a concurrency grace window, and a cache-backed denylist. Optional, feature-gated 2FA (TOTP) and passkeys (WebAuthn). It deliberately is **not** Passport/Sanctum/OAuth — first-party, so no authorization-code/PKCE ceremony. Architecture is modeled on Sanctum.

User-facing docs live in `docs/` (start at `docs/README.md`; `docs/architecture.md` has the design rationale, standards mapping, and security checklist). Customization recipes are in `docs/customization.md`.

## Commands

```bash
composer install
vendor/bin/pest                                   # full suite (Testbench, sqlite :memory:, array cache)
XDEBUG_MODE=coverage vendor/bin/pest --coverage   # coverage
vendor/bin/pint                                   # lint (Laravel preset, pint.json)
php artisan lukk:secret                           # generate LUKK_SECRET into .env
php artisan lukk:keygen                            # generate an RS256/ES256 signing keypair
php artisan lukk:prune                            # delete expired/revoked refresh tokens
```

## Architecture

- **Layering:** Controllers are thin (run an Action, return a Response contract) → **Actions** orchestrate and hold policy → **Contracts** are the swap seams → concrete impls live under `Tokens/`, `Refresh/`, `TwoFactor/`, `Passkeys/`, `Support/`, `Http/Responses/`.
- Rotation **policy** is in `Actions\RotateRefreshToken`; refresh **storage** is behind `Contracts\RefreshTokenRepository` (default `DatabaseRefreshTokenRepository`) — swap DB↔Redis without touching policy.
- Customization is Sanctum-style: the static `Lukk` hub (`authenticateUsing`, `tokenClaimsUsing`, `useRefreshTokenModel`, `disableScheduling`, `actingAs`), `config('lukk.features')` flags, and rebindable contracts.
- Config is **deep-merged** (`mergeConfigDeep`/`mergeConfig` in the provider), not Laravel's shallow `mergeConfigFrom` — a stale published config missing a nested key is backfilled from defaults (else a missing rate-limit key → `Limit(0)` → locks everyone out). Don't revert to `mergeConfigFrom`. Lists (`origins`/`audience`) are replaced wholesale, not merged.
- All migrations are **publish-only** (Sanctum/Passport convention) — nothing auto-loads. Each is its own publish group: `lukk-migrations` (core `refresh_tokens`), `lukk-two-factor-migrations`, `lukk-passkey-migrations`. Tests load them via `TestCase::defineDatabaseMigrations()`. 2FA/passkey routes are also feature-gated.

## Security invariants — do not break

- **One runtime dependency** (`firebase/php-jwt`). Never hand-roll JWS, TOTP, or WebAuthn. The 2FA/passkey libs are the only sanctioned extra deps — `suggest` + `require-dev`, gated behind `features.two_factor`/`features.passkeys`, never autoloaded unless enabled.
- **Alg pinning:** always decode with an explicit algorithm; reject `alg=none` and alg-mismatch. Validate `iss`/`aud`/`exp`/`nbf` every request.
- Refresh tokens are **opaque**, stored only as `sha256`, never logged, never serialized into any client bundle/hydration payload.
- Rotation + reuse detection are the point — **post-grace replay must revoke the whole family**. A false-positive family revoke under normal concurrency is a release blocker; TDD the rotate policy.
- **Revoke-then-throw happens OUTSIDE the rotate transaction.** The transaction returns a `RotationOutcome`; `killFamily` → `RevokeSession` runs after commit and dispatches `Events\RefreshTokenReused`. Revoking inside the transaction then throwing rolls back the revoke while the denylist write persists — an inconsistency hole. Keep the event firing.
- Token responses (`EmitsTokens`) must stay `Cache-Control: no-store`. Login must stay **constant-time** — the unknown-user path runs an equivalent `Hash::check`; don't "optimize" it away.
- **2FA:** TOTP secret encrypted (not hashed); recovery codes salted+hashed + single-use; TOTP single-use within its window (replay cache); challenge single-use + short TTL + account-throttled.
- **Passkeys:** sign-count regression rejected **but `signCount==0` never flagged** (synced passkeys); `credential_id` globally unique; COSE key encrypted at rest.
- **Concurrency:** keep sibling/grace (the grace branch mints a fresh sibling, never a false logout). Don't switch to strict CAS — direct non-BFF clients can't be forced to single-flight.
- Default **HS256**; RS256/ES256 + JWKS + `kid` key rotation are implemented behind the contracts (`Tokens\Jwt\KeyRing` resolves signing/verification material; the alg is pinned from config and **never read from the token header** — the alg-confusion defense). Stay on HS256 until an independent verifier actually exists. The JWKS JWK is hand-encoded from `openssl_pkey_get_details` — do not add a JWK library (one-runtime-dependency rule).

## Gotchas

- **Testing JWT time claims:** `firebase/php-jwt` validates `exp`/`nbf` against real `time()`, but the issuer stamps them from Carbon. **Mint at a travelled clock and verify at the real one** — `$this->travel(±N)->seconds(fn () => issuer()->accessToken(...))`. Don't mutate `JWT::$timestamp`.
- `ForceJsonRequest` (on the `/auth/*` route group, and exposed to consumers as the opt-in `lukk.force-json` alias) forces `Accept: application/json` so the routes always render JSON errors. It **must** sort before `Authenticate` — the provider does `addToMiddlewarePriorityBefore(AuthenticatesRequests::class, ...)` because `Authenticate` is high in the framework priority and otherwise resolves the guest redirect (`route('login')` → 500) before the forced header lands. That priority registration + the alias are wired **unconditionally** in `boot()` (not gated on `lukk.routes`), so the alias works on a consumer's own `auth:api` routes even in a verify-only service. Don't demote it to a plain group middleware; `shouldRenderJsonWhen` does not cover this path. lukk does **not** mutate the global guest redirect (`Authenticate::redirectUsing`/`redirectGuestsTo`) — that would break a hybrid app's web login; the alias is the surgical, opt-in alternative.
- Controllers are resource-oriented: one resource (or single-action `__invoke`) controller per concern, using resourceful verbs (`store`/`destroy`/`index`) — not one god-controller. They stay thin (run an Action, return a Response contract).
- `ConfirmablePasskeyController` **method-injects** `FinishPasskeyLogin` (not constructor) so the password path (`ConfirmablePasswordController`) doesn't require the optional WebAuthn ceremony.
- `firebase/php-jwt` is pinned `^7`, which hard-enforces a ≥256-bit HMAC secret — a short `LUKK_SECRET` throws instead of weakly signing.
- `final` is removed from all `src/` classes (user preference; keeps the refresh-token model extensible for `useRefreshTokenModel`).
- Tests split `tests/Unit/` (tests a class/action directly) vs `tests/Feature/` (hits an HTTP route), with `Feature/Console/` for command tests — Sanctum/Passport convention. Domain Pest groups: `pest --group={passkeys,two-factor,refresh,confirmation}`.
- Pest helpers in `tests/Pest.php`: `start()`, `rotate()`, `revokeSession()`, `revokeAll()`, `verifier()`, `issuer()`, `confirmedHeaders()`. `tests/Fixtures/FakeWebAuthnCeremony` drives passkey orchestration deterministically.
- Guard memoization: a second HTTP request in one test reuses the first request's resolved user. When two requests must act as different users (or model the per-request boundary), call `$this->app['auth']->forgetGuards()` between them.
- Time-boundary tests (`RotateRefreshTokenTest`) `freezeSecond()` in `beforeEach` — the grace check compares integer-second timestamps, so an unfrozen `rotate()`+`travel()` can straddle a wall-clock second and flake. Don't remove the freeze.
- `PasskeyIntegrationTest` drives the bare `WebauthnEmulator\Authenticator` with random keys. The emulator once emitted unpadded EC coords (`openssl_pkey_get_details` strips leading zeros → ~1/128 keys had a 31-byte x/y that `web-auth/cose-lib` rejects with a 500) — **fixed upstream in `pronin/webauthn-emulator` 1.2.2** (PR #5 left-pads the coordinates in `getCoseKey()`). The dep is therefore pinned `^1.2.2`; the old `FixedKeyAuthenticator` fixture workaround has been removed.
