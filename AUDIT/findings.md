# Findings — detailed

Ranked by exploitability × impact. Each: severity + CVSS 3.1, CONFIRMED/THEORETICAL, `file:line`, spec/CWE, PoC/repro, remediation. See [`README.md`](./README.md) for the executive summary and the list of invariants that held.

Legend: **CONFIRMED** = full code path traced and (where noted) reproduced; **THEORETICAL** = looks risky but could not be exploited as built (usually needs a host misconfiguration or a key/upstream compromise).

---

## MEDIUM

### RATE-1 — No IP-independent per-account login lockout (distributed brute force)
- **Severity:** Medium. CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` = **5.9** (high attack complexity: needs many source IPs).
- **Status:** ✅ **FIXED (2026-07-02)** — added an IP-independent per-account failure counter (`account_max_attempts`, default 20) alongside the existing `email|ip` bucket, and now `trim()` the email in the key (also closes RATE-2). Regression tests in `tests/Feature/RateLimitTest.php` ("caps failures per account across changing source IPs", "does not let trailing whitespace split the per-account login bucket"). Was CONFIRMED via PoC before the fix.
- **File:** `src/Auth/LoginRateLimiter.php:46`; coarse per-IP cap at `src/LukkServiceProvider.php:272-277`.
- **Spec/CWE:** CWE-307, NIST SP 800-63B §5.2.2, OWASP ASVS 2.2.1.

```php
public function key(Request $request): string
{
    return Str::transliterate(Str::lower((string) $request->input('email')).'|'.$request->ip());
}
```

The failures-only limiter the docblock calls "per-account" is keyed on `email|ip`. Because the source IP is in the key, the effective cap is `max_attempts` (default 5) **per IP per account** — there is no counter keyed on email alone. The route-level `lukk-login` throttle (`ip_max_attempts`, default 30) is *also* per-IP (`->by($request->ip())`), so neither bounds a distributed attack against a single account.

- **PoC / repro (pre-fix, CONFIRMED):** from `REMOTE_ADDR=10.0.0.1`, the 6th failed login for `victim@y.com` returned **429**; switching to `REMOTE_ADDR=10.0.0.2` and retrying the same account returned **422**, not 429 — the account was not globally locked, so guesses grew linearly with attacker IP count. The fixed behavior is now pinned by the regression test `tests/Feature/RateLimitTest.php` → "caps failures per account across changing source IPs (distributed brute force)", which asserts a fresh IP is blocked once the per-account cap is reached.
- **Observed vs expected:** Observed — no source-IP-independent account lockout. Expected (NIST/OWASP) — an account-scoped failure counter independent of source IP.
- **Caveat:** This mirrors Laravel Fortify/Breeze `ThrottlesLogins` exactly, so it is an accepted framework convention, not a lukk-specific regression — hence Medium, not High. Reuse detection + `no-store` + constant-time responses are unaffected.
- **Remediation:** add an email-only failure counter alongside the existing `email|ip` one, e.g.:

```php
public function tooManyAttempts(Request $request): bool
{
    return $this->limiter->tooManyAttempts($this->key($request), $this->maxAttempts)
        || $this->limiter->tooManyAttempts($this->accountKey($request), $this->accountMaxAttempts);
}
private function accountKey(Request $request): string
{
    return 'acct|'.Str::transliterate(Str::lower(trim((string) $request->input('email'))));
}
```
Choose `accountMaxAttempts` higher than `maxAttempts` (e.g. 20/decay) so legitimate multi-device users aren't locked, but a distributed attack is bounded. Document that this is a per-account global cap.

---

## LOW

### TOTP-1 — TOTP replay cache is not atomic (same-instant double-accept)
- **Severity:** Low. CVSS 3.1 `AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N` = **3.4**.
- **Status:** ✅ **FIXED (2026-07-02)** — replaced the `has()`+`put()` sequence with the atomic `Cache::add()` (returns false if the key already exists), so two concurrent requests can't both claim the same code. Was CONFIRMED (code); race is concurrency-only.
- **File:** `src/TwoFactor/Google2FaTotpProvider.php:46-50`.
- **Spec/CWE:** CWE-367 (TOCTOU), RFC 6238 §5.2.

```php
if ($this->cache->has($key)) {
    return false;
}
$this->cache->put($key, true, (2 * $this->config['window'] + 1) * 30);
```

`has()`+`put()` is not atomic: two concurrent requests presenting the same valid code can both pass `has()==false` before either `put()`, so both accept. Impact is bounded — the login flow's challenge token is single-use (jti denylist) and per-account throttled — so this mainly affects a same-instant double-accept on `ConfirmTwoFactor`.
- **Remediation:** use the atomic add (returns `false` if the key already exists):

```php
if (! $this->cache->add($key, true, (2 * $this->config['window'] + 1) * 30)) {
    return false;
}
return true;
```

### BFF-1 — Server-side proxies follow upstream 3xx (confirmation header / refresh body re-emitted)
- **Severity:** Low. CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` = **5.9** but gated on a trusted-upstream flaw → treat as Low.
- **Status:** ✅ **FIXED (2026-07-02)** — set `redirect: 'manual'` on all three call sites (`bff.ts`, `utils/refresh.ts`, `api-proxy.ts` via `fetchOptions`). `bff.ts` now rejects an opaque/3xx upstream response with a 502; `refresh.ts` treats it as a failed refresh (→ null). Regression tests added to `packages/nuxt/test/bff.test.ts`. Was THEORETICAL (needs an open redirect on the trusted upstream).
- **Files:** `packages/nuxt/src/runtime/server/bff.ts:56`, `.../server/utils/refresh.ts:29`, `.../server/api-proxy.ts:102`.
- **Spec/CWE:** CWE-918, CWE-200, RFC 9700.

All three use Node/undici `fetch`/`proxyRequest`, which default to `redirect: 'follow'`. undici strips `Authorization`/`Cookie` on cross-origin redirects (Bearer protected), **but**: `bff.ts:54` attaches the custom header `X-Lukk-Confirmation` (not stripped across redirects), and `refresh.ts:32` sends `{ refresh_token }` in the POST **body** (preserved on 307/308). A cross-origin 3xx from the upstream would re-send those to the redirect host.
- **Remediation:** set `redirect: 'manual'` (or `'error'`) on all three call sites and reject/re-validate any 3xx against `resolveTarget`.

### RATE-2 — Login limiter key not trimmed → per-account bucket split on MySQL
- **Severity:** Low. CVSS **3.7** (`AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`).
- **Status:** THEORETICAL (MySQL/MariaDB provider only).
- **File:** `src/Auth/LoginRateLimiter.php:46`.
- **Spec/CWE:** CWE-307.

The key normalizes case + transliterates but does not `trim()`. MySQL `VARCHAR` comparison is trailing-space-insensitive, so `email="victim@x.com "`, `"victim@x.com  "`, … all match the same user row in `retrieveByCredentials()` but land in distinct limiter buckets (each a fresh `max_attempts`). Leading whitespace doesn't match in MySQL; Postgres is space-sensitive, so impact is narrow (and a multi-IP attacker already wins via RATE-1). **Remediation:** `trim()` the email before keying (and prefer keying on the canonical value the provider matches).

### RATE-3 — IP component is attacker-controlled iff the host trusts proxies broadly
- **Severity:** Low (host-config dependent). **Status:** THEORETICAL.
- **File:** `src/Auth/LoginRateLimiter.php:46`, every `->by($request->ip())`.
- **Spec/CWE:** CWE-348, CWE-307.

Laravel 12 trusts no proxies by default (`$request->ip()` = `REMOTE_ADDR`, not spoofable) → safe out of the box. If a consumer sets `TrustProxies` to `*`, `X-Forwarded-For` becomes attacker-controlled and a single host can reset both the per-IP cap and mint unlimited per-account buckets (turning RATE-1 into a single-host attack). **Remediation:** document as a hard deployment prerequisite ("do not trust proxies you don't operate").

### LOGIN-1 — Timing equalizer cost may not match stored-hash cost; first-call double-op
- **Severity:** Low. **Status:** THEORETICAL.
- **File:** `src/Actions/AttemptLogin.php:100-105`.
- **Spec/CWE:** CWE-208.

`timingHash()` precomputes `Hash::make('lukk-timing-equalizer')` at the **default** driver/cost. If stored password hashes use a different algorithm/work factor (rehash policy, driver mismatch), the unknown-user `Hash::check` (vs equalizer) and known-user `Hash::check` (vs real hash) diverge in time — a residual enumeration oracle. Also, the first unknown-user login per worker pays `Hash::make` + `Hash::check` before the static memo warms. **Remediation:** derive the equalizer from `config('hashing')` (same algo/cost), and warm the memo at boot.

### CHAL-1 — ChallengeToken doesn't require `exp`; `sub` not type-guarded
- **Severity:** Low (defense-in-depth). **Status:** THEORETICAL (not reachable without the signing key).
- **File:** `src/Auth/ChallengeToken.php:88-113` (`decode`), `:63/:85`.
- **Spec/CWE:** RFC 7519 §4.1.4, CWE-613.

Unlike the access path (`FirebaseTokenVerifier.php:68` re-checks `is_numeric($claims->exp)`), `ChallengeToken::decode` has no explicit `exp` requirement — a challenge minted without `exp` would be immortal. `issue()` always stamps `exp` and the token is server-signed, so this isn't exploitable, but it's an invariant inconsistency ("validate exp every request"). Same for `sub`: the access path forces a non-empty string, the challenge path casts blindly. **Remediation:** add to `decode`: `if (! is_numeric($claims->exp ?? null)) return null;` and an `is_string($claims->sub ?? null)` guard.

### PASSKEY-1 — credential_id registration race → uncaught QueryException (500 not 422)
- **Severity:** Low (robustness). **Status:** THEORETICAL.
- **File:** `src/Actions/FinishPasskeyRegistration.php:44-48`.
- **Spec/CWE:** CWE-391.

`findByCredentialId` pre-check is TOCTOU against the PK unique constraint. Two concurrent registrations of the same credential_id race past the check; the loser's `store()` throws an uncaught `QueryException` → 500 instead of the intended 422. Not an auth bypass (the DB PK still enforces global uniqueness). **Remediation:** catch the unique-violation and translate to the same 422 the pre-check returns.

### VERIFY-1 — `RequireVerifiedEmail` fails open when the request is unauthenticated
- **Severity:** Low (misuse). **Status:** THEORETICAL.
- **File:** `src/Http/Middleware/RequireVerifiedEmail.php:22`.
- **Spec/CWE:** CWE-306.

When `$request->user()` is null, `instanceof MustVerifyEmail` is false → `$next()` runs. If a host attaches `lukk.verified` to a route *without* an auth guard in front, unauthenticated requests pass. It's a supplementary gate (not an authenticator), and `RequireConfirmation` fail-closes to 423 in the same situation — the asymmetry is the foot-gun. **Remediation:** one docblock line requiring `lukk.verified` to sit behind an auth guard (or fail-close when the user is null).

---

## INFORMATIONAL

### DENY-1 — Cache-flush re-enables revoked access tokens for one `access_ttl`
`src/Support/CacheDenylist.php`, `src/Actions/RevokeSession.php:29`. The denylist fails **closed** on a throwing cache, but an unplanned flush / `cache:clear` / LRU eviction (not just TTL self-eviction) silently drops `fid` entries, so a revoked-but-unexpired access token is accepted again for up to `access_ttl` (default 900s). No new tokens can be minted (refresh state is DB-durable). Document that `denylist_store` must be a persistent store and that `cache:clear` re-enables revoked access tokens for one `access_ttl`.

### CONFIRM-1 — Confirmation token is a reusable sudo-window bearer (not single-use)
`src/Http/Middleware/RequireConfirmation.php:25` uses `verify()` (non-consuming), so a confirmation token is reusable for the whole `confirm.ttl` window (GitHub-style sudo, by design). It's bound to the authenticated subject, so replay also requires the victim's access token. Add an explicit `docs/` line so integrators don't assume single-use.

### PASSKEY-2 — `Passkey` model defines no `$hidden`
`src/Models/Passkey.php`. lukk never serializes the model directly (the repository selects only summary columns), but a consumer who serializes a `Passkey` would expose the *encrypted* `public_key` blob. Add `protected $hidden = ['public_key'];` as defense-in-depth.

### PASSKEY-4 — Passwordless login broken on real authenticators (registration didn't request a resident key)
- **Severity:** Medium (feature-broken on real browsers). **Status:** ✅ **FIXED (2026-07-02)** — found by the browser E2E (Phase B).
- **File:** `src/Passkeys/SpomkyWebAuthnCeremony.php` `registrationOptions()`.
- **Spec/CWE:** WebAuthn L3 §5.4.4 (residentKey), CWE-287.

`StartPasskeyLogin` is **usernameless** (empty `allowCredentials` → requires *discoverable* credentials), but `registrationOptions` set no `authenticatorSelection`, so a real authenticator created a **non-discoverable** credential that usernameless login can never find (`navigator.credentials.get()` → `NotAllowedError`). The node/emulator conformance passed only because the software authenticator is lenient — a real Chromium (virtual authenticator) surfaced it immediately. **Remediation (applied):** request `residentKey: required` + `userVerification` in `authenticatorSelection` (also closes PASSKEY-3). Verified across lukk's passkey tests, node conformance, and the browser E2E.

### PASSKEY-3 — User verification not demanded at passkey registration
`src/Passkeys/SpomkyWebAuthnCeremony.php:75-101`. UV is enforced at assertion (login/step-up) but `authenticatorSelection.userVerification` isn't set on registration options/verification. Minor consistency gap with the AAL2 intent; assertion-time enforcement is the operative gate.

### TFA-1 — `amr` inaccurate on the recovery-code path
`src/Http/Controllers/TwoFactorChallengedSessionController.php`. Stamps `amr:['pwd','otp']` even when the second factor was a recovery code, not TOTP. Per RFC 8176, the recovery-code path shouldn't claim `otp`. Cosmetic, but affects downstream AMR-based policy.

### ROTATE-1 — Expired-and-consumed replay drops the theft signal
`src/Actions/RotateRefreshToken.php:59-68`. The `expired` check precedes `consumedPastGrace`, so replaying a stolen token *after it expires* returns `expired` (plain reject) with no family revoke and no `RefreshTokenReused` event, even though it's a genuine theft indicator. Security impact is nil (expired tokens mint nothing) but the monitoring/alerting signal is lost. If reuse detection feeds alerting, evaluate `consumedPastGrace` before/independently of `expired` for already-rotated rows.

### BFF-2 — CSRF Origin check allows a missing Origin
`packages/nuxt/src/runtime/server/proxy-utils.ts:29-32`. `isForeignOrigin` allows a state-changing request with no `Origin`. Not browser-exploitable because the session cookie is `SameSite=Strict` (a cross-site request carries no cookie) — so CSRF is held via the cookie and the Origin check is a secondary layer. Note the reliance is on SameSite, not the Origin check.

### BFF-3 — Auth proxy forwards no `X-Forwarded-For` → upstream per-IP throttle collapses
`packages/nuxt/src/runtime/server/bff.ts:49-57` builds a fresh header set and forwards no XFF (stronger anti-spoofing than the app proxy), but the upstream then sees the Nitro egress IP for every user, so lukk's per-IP auth throttle becomes a single global bucket. Inconsistent with `api-proxy.ts:108`, which sets a trusted XFF from `getRequestIP(event, { xForwardedFor: false })`. Consider setting the same trusted XFF in `bff.ts`.

### CORE-1 — Trusted-upstream redirect surfacing in the client fetch
`packages/nuxt/.../composables/useLukkFetch.ts:43`, `.../utils/create-lukk-fetch.ts:69-72`. On an upstream 3xx, `navigateTo(location, { external: true })` navigates the browser to the `Location` — an open-redirect-ish behaviour if the *app's own* API returned an attacker-controlled `Location`. It's a deliberate "surface the redirect" feature assuming a trusted same-origin API (core `client.ts` instead throws on 3xx). Worth one doc line on the trusted-upstream assumption.

---

## Regression tests

The fixed findings are pinned by tests in the normal suite (no separate PoC scaffolding needed):
- **RATE-1** — `tests/Feature/RateLimitTest.php`: "caps failures per account across changing source IPs (distributed brute force)" and "does not let trailing whitespace split the per-account login bucket".
- **TOTP-1** — `tests/Unit/TwoFactorProviderTest.php`: "rejects reuse of a code within its window (replay)" (the atomic `Cache::add()` preserves this single-use guarantee; the fixed race is concurrency-only).
- **BFF-1** — `packages/nuxt/test/bff.test.ts`: the `redirect: 'manual'` and opaque/3xx rejection cases.
