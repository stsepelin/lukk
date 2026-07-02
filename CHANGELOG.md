# Changelog

All notable changes to `lukk` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-02

### Added

- Optional `Lukk\Http\Resources\UserResource` — an extendable base API Resource for your `user.endpoint` that emits the fields the lukk-js client reads (the identifier + a derived `email_verified` boolean), so `useLukkAuth().user` / `verified` work out of the box. Extend it and override `fields()` to add your own; a bare model or your own resource still works too (lukk doesn't own your user endpoint — this is a convenience).
- `cookie.secure` config (env `LUKK_COOKIE_SECURE`, default `true`) gating the direct-mode refresh cookie's `Secure` attribute. Set it `false` **only** for local development over plain http — a browser drops a `Secure` cookie on http even on localhost, so the session wouldn't persist; lukk then also strips the `__Host-` prefix from the cookie name (that prefix requires `Secure`). Never ship `secure=false`.

### Security

- **IP-independent per-account login lockout** (`LUKK_LOGIN_ACCOUNT_MAX_ATTEMPTS`, default 20/min). The login limiter now throttles per account too, not just per email+IP, bounding a distributed brute force that rotates source IPs against a single account. The unknown-user path stays constant-time.
- **Atomic TOTP single-use.** The one-time-use guard for a TOTP code now uses an atomic cache `add` (was a `has` + `put`), closing a same-instant double-accept race under concurrency.

### Fixed

- Passkey registration now requests a **resident (discoverable) credential** (`residentKey: required`, user verification advisory), so passwordless / usernameless login works — the ceremony previously didn't request one and discoverable login failed with `NotAllowedError`.

## [0.1.4] - 2026-07-01

### Added

- **Email verification** (opt-in via `features.email_verification`). First-party, stateless verification that rides Laravel's framework-default `email_verified_at` + `MustVerifyEmail` (no lukk migration). A **signed link** (`GET /auth/email/verify/{id}/{hash}`, outside the JSON-forcing group) verifies and content-negotiates a redirect to your SPA (`email_verification.frontend_url`, with `?verified=1`) or a `204` for a JSON client; `POST /auth/email/verification-notification` resends (throttled `lukk-email-verification`). A `lukk.verified` middleware gates routes with a **409** when the email isn't verified (read fresh off the user, never a token claim), and `email_verification.block_unverified_login` optionally refuses login with a **403**. lukk points Laravel's `VerifyEmail` notification at its signed route; verification fires the standard `Illuminate\Auth\Events\Verified`. See [docs/email-verification.md](docs/email-verification.md).

## [0.1.3] - 2026-07-01

### Added

- `lukk.force-json` middleware alias. Attach it to your *own* `auth:api` routes (`Route::middleware(['lukk.force-json', 'auth:api'])`) to get a clean `401` JSON instead of the guest-redirect `500` on an `Accept`-less request — surgically, without globally disabling the guest redirect (which would also drop a real web login's redirect). It reuses the existing `ForceJsonRequest` middleware (ordered ahead of `Authenticate`), is opt-in (registers nothing global until you attach it), and works in verify-only services (`routes => false`) too.

### Changed

- Auth request validation moved to FormRequests (`LoginRequest`, `TwoFactorChallengeRequest`, `PasskeyAssertionRequest`, `PasskeyRegistrationRequest`). A malformed input (e.g. `code[]=x`) now renders a `422` instead of a `500`.
- `lukk:prune` now keeps revoked-but-unexpired refresh tokens (deletes only rows past `expires_at`), so a replay of a revoked token still resolves to reuse detection (`reuse` + family cascade + `RefreshTokenReused`) instead of a generic reject; the rows self-delete once they expire.

### Security

- **Passkey `user_verification` now defaults to `required`** (was `preferred`). Passwordless login and passkey step-up are single-factor (possession), so enforcing user verification (biometric/PIN) makes them phishing-resistant (AAL2). Set `LUKK_PASSKEY_UV=preferred` if you must support authenticators that can't verify the user.
- `RevokeSession` writes the denylist entry **before** the DB revoke, so a mid-operation cache failure can't leave a family's access tokens live after its refresh tokens are revoked.
- Challenge/confirmation tokens (2FA, passkey step-up) sign and verify through the same `KeyRing` as access tokens — staying alg-pinned and working under an RS256/ES256 deployment (previously hard-coded to the symmetric secret, which broke asymmetric setups).
- The 2FA trait hides `two_factor_secret` / `two_factor_recovery_codes` from model serialization (matching Fortify), so returning your `User` model in a response no longer exposes the encrypted secret / hashed recovery blobs.
- The passkey ceremony now **pins the accepted COSE signature algorithms explicitly** (ES256 + RS256, matching the advertised `pubKeyCredParams`) instead of inheriting `web-auth/webauthn-lib`'s transitive default — so a future library-default change can't silently widen the allowed set (defense-in-depth; WebAuthn L3 §5.3/§7.2).

### Performance

- `KeyRing` now memoizes its verification `Key` set and loaded public-key PEMs per instance, so an asymmetric (RS256/ES256) deployment no longer re-reads key files or re-allocates a `Firebase\JWT\Key` on every token verification.

### Fixed

- JWKS EC coordinates are now left-padded to the curve field size (RFC 7518 §6.2.1.2). `openssl_pkey_get_details` strips leading zero bytes, so roughly 1 in 256 coordinates was published a byte short and strict JWKS consumers would reject the key. Only affects RS256/ES256 (specifically ES\*) deployments serving `GET /auth/jwks`; the default HS256 setup publishes an empty set and is unaffected.

## [0.1.2] - 2026-06-30

### Changed

- lukk's `/auth/*` routes now force `Accept: application/json` (a `ForceJsonRequest` middleware, ordered ahead of `Authenticate` in the framework priority), so authentication and validation failures always render a clean `401`/`422` JSON. This makes lukk's API immune to the host app's exception config and Laravel's default guest redirect, which otherwise 500s an `Accept`-less request (e.g. behind a BFF proxy that strips `Accept`) — `shouldRenderJsonWhen` does **not** prevent that, as it runs after the auth middleware has already thrown.

## [0.1.1] - 2026-06-29

### Changed

- Leaner Composer dist: `.gitattributes` export-ignore excludes tests, docs, CI, and dev tooling, so `composer require lukk/lukk` installs only the runtime code.
- Documented the BFF per-IP throttling caveat (auth traffic collapses to the BFF server's IP) in the deployment guide.

## [0.1.0] - 2026-06-28

### Added

Core token model:

- Short-lived HS256 access JWTs with full claim set (`iss/aud/sub/fid/jti/iat/nbf/exp`, `typ=at+jwt`).
- Optional asymmetric signing (RS256 / ES256) behind the same `TokenIssuer`/`TokenVerifier` contracts, for split auth-service / verify-only-API deployments: a `kid`-addressed key set, signing-key rotation with an overlap window (a retired key keeps verifying its live tokens), a `GET /auth/jwks` endpoint (JWK Set built without any extra dependency), and a `lukk:keygen` command. The algorithm is pinned from config and never read from the token header — the RS256↔HS256 confusion defense.
- Opaque, rotating refresh tokens (sha256 at rest) with reuse detection and family-cascade revoke.
- Concurrency grace window so single-flight refreshes don't trip reuse detection.
- Cache-backed denylist (by `jti`/`fid`) for instant revocation.

Guard & endpoints:

- `JwtGuard` request guard (`lukk-jwt` driver) and resource controllers: `POST /auth/login` + `/refresh`, `POST /auth/logout`, and `DELETE /auth/sessions` (revoke all) / `DELETE /auth/sessions/others` (revoke all but the caller, via `RevokeOtherSessions`).

Extensibility:

- Swappable contracts (`TokenIssuer`, `TokenVerifier`, `RefreshTokenRepository`, `Denylist`, response contracts).
- Static `Lukk` hub (`authenticateUsing`, `useRefreshTokenModel`, `actingAs`) and `HasRefreshTokens` trait.
- `Lukk::tokenClaimsUsing()` to add custom claims (e.g. roles) to the access token; standard claims cannot be overridden.
- Multiple audiences: `LUKK_AUDIENCE` is comma-separated, so one token can be minted for several services; each verifies when its own audience is listed (a single audience stays a string). Enables a split auth-service / verify-only-API topology — see `docs/deployment.md`.

Security:

- `RefreshTokenReused` security event on reuse/revoked family kill.
- `Cache-Control: no-store` on token responses and constant-time login (no user enumeration).
- The access-token verifier enforces the `typ=at+jwt` header, so a 2FA / step-up *challenge* token (same key, iss and aud) can never be presented as a bearer access token.
- A coarse per-IP login cap (`rate_limits.login.ip_max_attempts`) on top of the per-account failure limiter, bounding password spraying across many emails.
- Passkeys require `rp_id` and `origins` to be configured (fail loud rather than silently weak origin validation); passkey verification failures return a 4xx, never an uncaught 500.
- In cookie mode the `__Host-` refresh cookie is `SameSite=Strict` (and cleared with matching attributes on logout).
- An unknown / expired / revoked / reused refresh token returns a clean `401` (self-rendering `InvalidRefreshToken`), never an uncaught 500, without leaking which reason.
- Config is **deep-merged** from the package defaults, so a published config that predates a nested key is backfilled — preventing a missing rate-limit key from resolving to `0` (which would lock out every login).
- Unified, configurable rate limits under `lukk.rate_limits` — `login`, `two_factor`, `refresh`, and `passkeys`, each `{ max_attempts, decay_seconds }`. Login keeps a dedicated failures-only limiter (keyed on normalized email + IP, clears on success); the rest are named limiters (`lukk-refresh` / `lukk-passkeys` / `lukk-2fa`) you can also override via `RateLimiter::for()`. Two-factor additionally throttles per account (`sub`).

Multi-factor (opt-in):

- Two-factor authentication (TOTP + recovery codes), opt-in via `features.two_factor` + `pragmarx/google2fa`: enrol/confirm/disable/regenerate endpoints, a recovery-code **count** endpoint (`GET /auth/two-factor/recovery-codes` — codes stay hashed, so only the remaining count is surfaced, never the values), and a `2fa+challenge` login step. Secret stored encrypted, recovery codes salted+hashed (single-use), intra-window TOTP replay protection, account-keyed challenge throttle, and `amr` claims (`["pwd"]` / `["pwd","otp"]`) on issued tokens. `Auth\ChallengeToken` is a generic single-use challenge primitive (reused by passkeys).
- Step-up ("sudo") confirmation: `POST /auth/confirm-password` (or `/auth/confirm-passkey`) mints a short-lived `confirmation_token`, and the `lukk.confirm` middleware gates sensitive routes behind it (423 Locked otherwise). Reusable for your own routes; the 2FA + passkey management endpoints use it.
- Passkeys (WebAuthn / FIDO2), opt-in via `features.passkeys` + a `WebAuthnCeremony` adapter: passwordless registration/login (→ tokens with `amr: ["webauthn"]`), credential list/delete, and passkey-based step-up confirmation. Stateless cache-backed single-use challenges (keyed by user for registration, opaque `ceremony_id` for login), sign-count regression detection (`Events\PasskeyCloneDetected`, never flags `0`), globally-unique credential ids, COSE public key encrypted at rest. Storage behind `Contracts\PasskeyRepository` (`passkeys` table). `rp_id` and `origins` are required (no weak fallback); `passkeys.user_verification` (default `preferred`, set `required` for biometric/PIN) gates login and step-up.

Commands:

- `lukk:secret` Artisan command to generate the 256-bit HMAC signing secret and write `LUKK_SECRET` to `.env` (modeled on `jwt:secret`/`key:generate`; supports `--show` and `--force`).
- `lukk:keygen` Artisan command to generate an RS256/ES256 signing keypair (prints the PEMs and the env to set).
- `lukk:prune` command for expired/revoked tokens, scheduled daily by default (opt out via `Lukk::disableScheduling()`).

[Unreleased]: https://github.com/stsepelin/lukk/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/stsepelin/lukk/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/stsepelin/lukk/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/stsepelin/lukk/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/stsepelin/lukk/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/stsepelin/lukk/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/stsepelin/lukk/releases/tag/v0.1.0
