# lukk + lukk-js — Security & Hardening Audit

**Date:** 2026-07-02
**Scope:** `lukk` (PHP, Laravel 12/13 JWT auth package) and `lukk-js` (TypeScript client monorepo: `lukk-core` + `lukk-nuxt`).
**Type:** Authorized, local-only, white-box audit of a first-party self-owned codebase. Ownership independently verified (git remotes → `github.com/stsepelin/{lukk,lukk-js}`, matching `authors`/LICENSE holder and local git identity).
**Method:** White-box source analysis of every security-critical file, mapped against the invariants in `CLAUDE.md` and the relevant specs (below), corroborated by the existing test suites and (for the fixed findings) new regression tests. No external host was contacted.

---

## Executive summary

**Posture: strong.** Every security invariant the project documents held under adversarial tracing. Across both repos there are **zero confirmed exploitable vulnerabilities** — no auth bypass, no token forgery, no alg-confusion, no cross-token confusion, no SSRF, no token leakage to the browser or SSR payload, no prototype pollution, no enumeration oracle.

The findings are **hardening and defense-in-depth**: one confirmed brute-force resistance gap that matches Laravel Fortify's own convention (so it is a known-accepted pattern, not a lukk regression), and a set of low/informational items — several of which are behaviours that are safe *as built* but deserve an explicit line in `docs/` so integrators don't misuse them.

Baseline: `vendor/bin/pest` → **196 passed / 488 assertions** (green) before and after the audit.

### Findings by severity

| Sev | Count | Items |
|---|---|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 1 | RATE-1 (distributed per-account brute force — **CONFIRMED** via PoC) |
| Low | 8 | TOTP-1, RATE-2, RATE-3, LOGIN-1, CHAL-1, PASSKEY-1, VERIFY-1, BFF-1 |
| Informational | 9 | DENY-1, CONFIRM-1, PASSKEY-2, PASSKEY-3, TFA-1, ROTATE-1, BFF-2, BFF-3, CORE-1 |

Full detail, CVSS vectors, `file:line`, repro steps and remediation diffs are in [`findings.md`](./findings.md).

> **Update 2026-07-02:** the three top items below — **RATE-1, BFF-1, TOTP-1** — have been **FIXED** (with regression tests; both suites green). See `findings.md` for the per-finding status and the diffs. The remaining low/informational items are still open.

### Top items (ranked by exploitability × impact) — all three now FIXED

1. **RATE-1 — no IP-independent per-account login lockout** (`src/Auth/LoginRateLimiter.php:46`). The failures-only limiter is keyed on `email|ip`, so a distributed attacker gets `max_attempts` (5) guesses *per IP* against one account. Confirmed by PoC. Matches Fortify's convention; add an email-only counter if distributed brute force is in the threat model.
2. **BFF-1 — server-side proxies follow upstream 3xx** (`packages/nuxt/.../server/{bff,api-proxy}.ts`, `utils/refresh.ts`). `fetch`/`proxyRequest` default to `redirect: 'follow'`; the custom `X-Lukk-Confirmation` header and the refresh-token POST body would be re-emitted to a redirect host if the trusted upstream ever open-redirects. Set `redirect: 'manual'`.
3. **TOTP-1 — TOTP replay-cache is not atomic** (`src/TwoFactor/Google2FaTotpProvider.php:46-50`). `has()`+`put()` allows a same-instant double-accept of one code under concurrency. One-line fix: `Cache::add()`.

Everything else is low/informational hardening or documentation.

---

## Invariants tried hard to break — and HELD

Each was attacked by tracing the full code path (and, where noted, by the existing tests):

**JWT / crypto**
- Algorithm is pinned from config onto every `Key` and **never** read from the token header — `alg=none`, stripped signature, and HS↔RS/ES confusion all rejected (`KeyRing.php:75/81`, firebase's `constantTimeEquals(key.alg, header.alg)`; tests `AsymmetricTokenTest.php:50`).
- `kid` can only select among operator-trusted public keys; unknown/absent `kid` → reject (`AsymmetricTokenTest.php:64/74`).
- `iss`/`aud`/`exp`/`nbf`/`sub` validated on every access verify; `exp` re-checked explicitly because the library only validates it when present (`FirebaseTokenVerifier.php:55-75`).
- **Cross-token confusion blocked both ways** via the `typ` header (signature-covered): a challenge (`{kind}+challenge`) can't be used as an access bearer (`at+jwt`) and vice-versa (`FirebaseTokenVerifier.php:51`, `ChallengeToken.php:98`).
- JWKS emits only public members (`n`/`e`, `x`/`y`), never private material; EC coordinates are left-padded to the field size (RFC 7518 §6.2.1.2) (`KeyRing.php:117-175`).

**Refresh / rotation / denylist**
- Post-grace replay of a rotated token revokes the whole family; concurrent legit refreshes mint a sibling (no false-positive family kill) — serialized by `lockForUpdate()`, integer-second comparisons, no off-by-one (`RotateRefreshToken.php:48-91`).
- The family revoke runs **after** the transaction commits (revoke-then-throw outside the tx), so a rollback can't strand a denylist write (`RotateRefreshToken.php:86-108`).
- Refresh secrets are 256-bit CSPRNG, stored only as `sha256`, never logged or serialized (`FirebaseTokenIssuer.php`).
- Denylist fails **closed** on a throwing cache (propagates → 401/500, never an allow); denylist TTL ≥ token lifetime (`RevokeSession.php:29`).

**Login / guard**
- Constant-time: the unknown-user path runs an equivalent `Hash::check` against a memoized timing hash; identical 422 body for unknown vs wrong-password; no pre-auth 2FA/verify enumeration oracle (`AttemptLogin.php:63-69`).

**2FA / passkeys**
- TOTP secret encrypted (not hashed); recovery codes ~119-bit, bcrypt-hashed, single-use under a row-locked transaction; TOTP single-use within its window; challenges single-use + short TTL + per-account throttle bound to the verified `sub`.
- Passkey sign-count regression rejected while `signCount==0` is exempt; `credential_id` globally unique (PK + app pre-check); COSE algs pinned to ES256/RS256; UV enforced at assertion; `rp_id`/origins fail-loud.

**Email verification / confirmation / DTO / caching**
- Signed-URL verify is server-verified and unforgeable; hash bound to the *current* email (stale-email links fail); no open redirect (destination is config-only); idempotent replay.
- Step-up confirmation is server-enforced on every sensitive route, cross-user/expired tokens rejected, kind-isolated from 2FA challenges.
- `UserResource` exposes only `id` + derived `email_verified`; no secret/PII leakage; no mass assignment.
- All token-bearing responses carry `Cache-Control: no-store` (both BFF-body and cookie modes).

**lukk-js BFF / SSR / client**
- SSRF contained: the upstream URL is a fixed config base + a `startsWith`-prefix-checked subpath; traversal/`%2e%2e`/authority-smuggling/absolute-URL override all rejected (`proxy-utils.ts:11-22`).
- No token reaches the browser, the response body, a non-HttpOnly cookie, or the `__NUXT__`/SSR payload; upstream `Set-Cookie` is stripped (the sealed session is never forwarded regardless of allow-list); hydrated pages set `no-store`.
- Session cookie is `__Host-`-compatible (`Secure; HttpOnly; SameSite=Strict; Path=/`, no Domain); a tampered/wrong-secret/expired seal fails closed to anonymous without minting a cookie.
- No SSR cross-request bleed (only module state is a per-session-id single-flight `Map`, deleted on settle).
- Client: prototype pollution blocked (null-prototype nodes for dotted 422 keys; by-reference user shaping); a `{data}`/error body can't fake a session; cross-origin credential attachment refused; the 401→refresh loop is bounded to one retry; route guards are fail-safe UX gates that document the server as the real boundary.

---

## Performance (static analysis)

Method: code inspection of hot paths + schema. **Load benchmarks with p50/p99 numbers were not run** — this pass is static (the live integration-app benchmark harness was out of scope for this iteration; see Methodology). No performance regression found; notes:

- **JWT verify** (per request): one `JWT::decode` (HMAC or one asymmetric verify) + `KeyRing` material is **memoized per instance** (`KeyRing.php:70-85`, one `Key` alloc, not per verify) + a batched denylist read (`CacheDenylist::hasAny` uses `store->many()`, a single round-trip for jti+fid). No per-request key parsing or file I/O on the symmetric path.
- **Refresh rotation**: the hot lookup `findByHashForUpdate` hits the **unique** `token_hash` index; family revoke and prune use the indexed `family_id`/`revoked_at`/`expires_at` columns (`create_refresh_tokens_table.php`). No N+1. Rotation is a single row-locked transaction; contention is per-family, not global.
- **Login**: one bcrypt `Hash::check` on every path (intended constant-time cost). The timing-equalizer hash is memoized per worker (`AttemptLogin.php:100-105`) — see LOGIN-1 for a first-call double-op note.
- **BFF**: request bodies are streamed (`streamRequest: true` / raw-body relay), not buffered; the hot read path unseals the session **read-only** (one iron-open), opening the read-write session only on an actual token write; concurrent refreshes collapse to a single upstream `/refresh` via a per-session single-flight (`utils/refresh.ts`).
- **Boot**: config is deep-merged once; rate limiters are registered as closures. No blocking boot work observed.

---

## Methodology & environment

- **Environment:** PHP 8.5.7, Composer 2.9.7, `firebase/php-jwt ^7`, Testbench (sqlite `:memory:`, array cache). macOS (darwin 25.5.0). `lukk` baseline suite green (196/488).
- **Approach:** seven parallel white-box audit passes (JWT crypto; refresh/rotation/denylist; login/rate-limit/guard; 2FA/passkeys; email-verify/confirmation/guards/DTO; BFF/SSR; core client/composables), each reporting CONFIRMED vs THEORETICAL with `file:line`, spec/CWE, and remediation. The lead independently re-read the crown-jewel files (verifier, KeyRing, guard, rotation, denylist, challenge, login, email verify, BFF proxy) and empirically confirmed the top finding with a runnable PoC.
- **What was NOT done (honest scope):** no live served Laravel/Nuxt target was stood up and no crafted-HTTP fuzzing or load benchmark was run against one. The existing Feature tests already exercise the real HTTP routes and the Unit tests drive the crypto/token classes directly; findings that would need end-to-end HTTP to *confirm* are marked THEORETICAL. RATE-1 was confirmed with a runnable test before being fixed; the fixed findings are now pinned by regression tests in the normal suite (see the "Regression tests" section in `findings.md`).

### Specs referenced
RFC 8725 (JWT BCP), RFC 7519/7515/7517/7518 (JWS/JWK/JWA), RFC 9700 (OAuth 2.0 Security BCP), IETF OAuth 2.0 for Browser-Based Apps (BFF), RFC 6265bis (cookies), W3C WebAuthn L3, RFC 6238/4226 (TOTP/HOTP), RFC 8176 (AMR), OWASP ASVS 5.0 / API Top 10 (2023) / Top 10 (2021) / cheat sheets, NIST SP 800-63B. CWE mappings per finding in `findings.md`.

