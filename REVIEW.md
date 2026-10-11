# REVIEW.md — review rules for `lukk`

**Every review of this repository applies these rules.** That covers pull-request bots (Greptile, Copilot), Claude Code and its subagents, and human reviewers. A review that doesn't check a change against the specs below, or doesn't cite the clause a finding rests on, is incomplete. The binding project invariants are in [`CLAUDE.md`](./CLAUDE.md); this file is how a review proves a change keeps them.

Sister files: `lukk-js/REVIEW.md` (client, BFF proxy) and `lukk-docs/REVIEW.md` (documentation). The method, severity bar and recurring-defect sections are shared — when one changes, change all three.

---

## 1. Method (mandatory)

1. **Scope.** Review the diff *and* every path it touches: callers, the contract it implements, the config keys it reads, the migrations behind the columns it uses. A fix is reviewed together with the code it fixes.
2. **Map the change to the spec table (§4).** For each touched area, list the clauses that apply, and check each one. Say which clauses you checked, not only which ones failed.
3. **Look for the opposite defect.** Every fix in this repo's history that closed one hole risked opening the inverse one:
   - a 401 that hides a 500, or a 500 that should be a 401;
   - a lockout that becomes a bypass, or a bypass that becomes a lockout;
   - a false logout that becomes an accepted replay;
   - an availability fix that becomes an assurance downgrade.

   For each fix, name its inverse and show it isn't introduced.
4. **Verify by running it.** A finding is CONFIRMED only when you reproduced it with a test, a probe or a real-engine run, and you say how. Anything you only reasoned out is PLAUSIBLE and is labelled that way. Run database-behaviour claims on the real engines (§5.3).
5. **Check that tests pin the change.** Run each new test against the parent commit's `src/`. A test that passes there pins nothing. Name such tests.
6. **Report format.** For each finding give: severity (§2), `file:line`, a concrete scenario (inputs → wrong output), the clause or invariant broken, and the minimal fix. Order the findings most severe first. Put deliberate deviations (§6) and below-the-bar items in a separate list, never among the findings.

## 2. Severity and the release bar

| Severity | Meaning |
|---|---|
| **Blocker** | An unauthenticated user, an ordinary signed-in user, or a malicious site can trigger it on a standard install. The impact is one of: account takeover, auth bypass, assurance downgrade (AAL2 → AAL1), token or session leak, a false family revoke or false logout under normal use, lockout of legitimate users, a 500 on a normal request, data loss, or a GDPR export/erasure gap. |
| **Major** | The same impacts, but it needs a documented non-default setting (a `lukk` feature flag, a second guard, cookie mode, a Laravel hashing option) or a co-issuer holding the signing key. |
| **Minor** | Hardening, defense in depth, misleading errors, docs drift. |

A **standard install** means: the stock `User` with `id()`, the stock `EloquentUserProvider`, the default `config/lukk.php`, and PostgreSQL, MySQL or SQLite.

Blockers stop a merge. Majors are fixed before release, or written into [Known limitations](https://stsepelin.github.io/lukk-docs/security#known-limitations) with the reason. Minors go into an issue.

## 3. What a review must always run

```bash
vendor/bin/pint --test
vendor/bin/phpstan analyse -c phpstan-src.neon
XDEBUG_MODE=coverage php -d memory_limit=-1 vendor/bin/pest --coverage --min=100
docker compose up -d
LUKK_TEST_PGSQL=1 vendor/bin/pest --group=concurrency
LUKK_TEST_MYSQL=1 LUKK_TEST_ENGINE=mysql vendor/bin/pest --group=concurrency
vendor/bin/pest --mutate --class='<each changed class>' --covered-only --parallel
```

**Mutation runs.** A TIMEOUT proves nothing; see CLAUDE.md. Re-run any timeout with `calculateTimeout()` raised to `duration * 10 + 60`, then restore `vendor/`. Hand-delete `?->` statements, because Pest never removes a nullsafe call. A `@pest-mutate-ignore` covers the whole line, so check what else on that line it silences.

## 4. The specifications lukk relies on

Each row: the clause → what it requires of lukk → what a review checks. When a change touches the area, every row in that area applies.

### 4.1 JWT, JWS, JWK — access, challenge and confirmation tokens

| Clause | Requirement in lukk | Review checks |
|---|---|---|
| RFC 8725 §3.1 | Verify the algorithm. | Decoding always passes an explicit, config-pinned algorithm, never one read from the header. `alg=none` and any algorithm mismatch are rejected. |
| RFC 8725 §3.9 | Validate the audience. | `aud` is checked on every request, and the token is rejected before any user is resolved (reject-before-resolve). |
| RFC 8725 §3.10 | Don't trust received claims. | Every claim is type- and range-checked before use: `sub`, `fid`, `jti`, `iat`, `amr`, `auth_time`, `scope`, `pin`. A malformed claim gives 401, never a 500 and never a `TypeError`. |
| RFC 8725 §3.11, RFC 9068 §2.1 | Explicit typing. | Access tokens carry `typ=at+jwt` and it is **asserted**. A 2FA challenge or step-up token (same key, `iss` and `aud`) can never pass as a bearer, and the reverse holds too. |
| RFC 7519 §2 | NumericDate. | Time claims are bounded to [epoch, 9999], may be fractional, and a non-numeric value is refused. |
| RFC 7519 §4.1.3–4.1.5 | `aud`, `exp`, `nbf`. | Validated on every request. `leeway` is clamped to 0–300 s (§4.1.4, "some small leeway") everywhere it is used, including denylist TTLs. |
| RFC 7515 §4.1.11 | `crit`. | An unknown critical header is rejected. lukk emits none. |
| RFC 7518 §3.2 | HMAC key size. | An HS256 secret is ≥ 256 bits; firebase/php-jwt v7 enforces this. A shorter secret must throw, never sign weakly. |
| RFC 7518 §6.2.1.2, RFC 7517 | JWKS. | EC `x`/`y` are left-padded to the full coordinate length. `kid` is used to rotate keys, never to choose the algorithm. The JWK is hand-encoded; no JWK library (one-runtime-dependency rule). |
| RFC 9068 §2.2, §4 | Access-token claims and validation. | `iss`, `aud`, `sub`, `exp`, `iat`, `jti` and `scope` follow RFC 9068's shape. lukk does not claim conformance: there is no `client_id`. |
| RFC 9068 §2.2.3, OIDC Core §2 | `auth_time`, `amr`. | `auth_time` is the real sign-in time stored with the session (`SessionAuthentication`), never derived from `refresh_ttl`. Both claims are reserved and survive refresh; a `tokenClaimsUsing` hook can neither forge nor erase them. |
| RFC 8176 | `amr` values. | Only registered values. A single-factor passkey plus TOTP is `pop`, `user`, `otp`, and **not** `mfa`. |
| RFC 6750 §3, §3.1 | Bearer errors. | `WWW-Authenticate` uses `invalid_token` or `insufficient_scope`. The error body never says *why* a token failed beyond those codes. |
| RFC 6749 §3.3 | `scope` syntax. | Abilities use the scope-token charset (no space, no `"`, no `\`) and are bounded (128 B per ability, 2048 B per claim). `NULL` means derive and `''` means pinned to nothing; never conflate them. |
| RFC 8693 | `act` (impersonation). | Impersonation tokens are short-lived, can't be refreshed, and carry `act` naming the real admin. |

### 4.2 Refresh tokens, rotation, revocation

| Clause | Requirement in lukk | Review checks |
|---|---|---|
| RFC 9700 §4.14 | Protect refresh tokens. | Tokens are opaque and random, stored only as `sha256`, never logged, and never serialised into a response body except the token pair itself. |
| RFC 9700 §4.14.2 | Rotation, and replay → revoke. | A replay after the grace window revokes the **whole family**. A false family revoke under normal concurrency is a release blocker. The grace window is a deliberate deviation (§6). |
| RFC 6749 §5.1 | Token responses. | `Cache-Control: no-store, private` on every response that carries a token (`EmitsTokens`). |
| RFC 7009 §2.1, §2.2 | Revocation. | Logout works without a valid access token. Revoking an unknown token is not an error. A revoke covers the **longest** access-token lifetime still alive (`LongestAccessTtl`), not the configured one. |
| OWASP ASVS 5.0 V7.4.1 | Logout really invalidates. | `DELETE /auth/sessions` revokes every family plus the presented bearer, including a co-issuer token with no `fid`. A bulk revoke acts on the families it read, never on sessions started meanwhile. |
| CLAUDE.md invariant | Revoke-then-throw. | The family revoke and the `RefreshTokenReused` event run **after** the rotate transaction commits. No application callback (`abilitiesUsing`, `tokenClaimsUsing`) and no model event runs under the row lock (`saveQuietly`). |

### 4.3 Authentication assurance — NIST SP 800-63B-4, OWASP ASVS 5.0

| Clause | Requirement in lukk | Review checks |
|---|---|---|
| 800-63B-4 §2.2.1 | AAL2 needs two **different** factors. | Two possession factors are not `mfa`. A password or biometric comparison is required for two single-factor authenticators to count. |
| 800-63B-4 §2.2.3 | Reauthentication. | Password step-up in an `mfa` session is allowed only within `confirm.mfa_max_age` of the real `auth_time`. A session with no stored sign-in time fails closed. |
| 800-63B-4 §3.1.1.2 | Password verifiers. | No composition rules. Long passwords are accepted. Never truncate silently: bcrypt's 72-byte limit is refused, not cut. Compare in constant time. A rehash at login must never revert a concurrent password change (it is a conditional UPDATE on the checked hash). |
| 800-63B-4 §3.1.4, §3.1.6 | OTP and possession authenticators. | TOTP is possession. A TOTP is single-use within its window (a replay cache using an atomic `add()`), and the challenge is single-use, short-TTL and throttled per account. |
| 800-63B-4 §3.2.2 | Rate limiting. | The opt-in lockout caps *consecutive* failures. Each attempt is reserved before verification. A correct credential on the capping attempt does not lock, and `AccountLocked` fires exactly once. The account and the fold are both counted. |
| 800-63B-4 §4.1.2.1 | Binding authenticators at the highest available AAL. | Any step-up that binds or removes an authenticator, changes the password, or exports or erases the account must meet the account's highest available level. A stored password counts as **present** unless lukk can *prove* nothing could ever match it (`crypt()`, stock provider and hasher only). Any doubt resolves toward the higher bar. |
| 800-63B-4 §4.2 | Recovery is announced. | Reset, recovery-code use and authenticator binding or removal dispatch events (`RecoveryCodeUsed` …) so the user can be told out of band. |
| ASVS 5.0 6.1.1, 6.3.1 (4.0.3 V2.2.1) | Anti-automation. | Login, forgot-password, reset, 2FA, confirm and refresh are throttled. Buckets key on the identifier **fold**, never on the resolved account (§6). `ip_max_attempts` caps password spraying. |
| OWASP Authentication Cheat Sheet | No user enumeration. | Login is **constant-time**: the unknown-user path does an equivalent `Hash::check`, the failure path runs in a `Timebox`, and the work is equal (same lookups and derivations) for a real and an unknown account. The same responses, statuses, `Retry-After` and bucket timers for both. |
| OWASP Password Storage Cheat Sheet | Hashing. | Use Laravel's hasher. Auto-rehash only under exactly `EloquentUserProvider` with the app's own hasher (a custom one may pepper). |

### 4.4 Second factors — RFC 6238 / RFC 4226 (TOTP), WebAuthn Level 3 (passkeys)

| Clause | Requirement in lukk | Review checks |
|---|---|---|
| RFC 6238 §5.2 | Validation window and replay. | A ±1 step window at most. A code is accepted once per window. The secret is encrypted at rest, not hashed. Recovery codes are salted, hashed and single-use, with enough entropy. |
| WebAuthn L3 §4 | `uvInitialized`. | UV counts toward `mfa` only on a credential already `uvInitialized`. lukk never promotes that flag itself. |
| WebAuthn L3 §5.1, §5.3 | Credential JSON, allowed algorithms. | The pinned algorithm list is passed explicitly, so a library default can't widen it. `id` and `rawId` are validated, and malformed input gets a 422, never a 500. |
| WebAuthn L3 §5.4, §5.5, §15.1 | Ceremony timeouts. | The challenge is server-generated, single-use and bound to a UUID `ceremony_id`. Its TTL covers the advertised timeout plus a margin. |
| WebAuthn L3 §6.1.1 | Signature counter. | A regression is rejected, **but** a stored counter of 0 is never flagged (synced passkeys). Once the stored counter is non-zero, an incoming 0 is a regression. The counter is written forward-only, so concurrent assertions can't both pass. |
| WebAuthn L3 §6.2.3 | Authenticator types. | A TOTP does not raise a passkey to multi-factor. |
| WebAuthn L3 §7.1, §7.2 | Registration and assertion verification. | Check origin and RP ID binding, UP and UV flags, the signature, `credential_id` global uniqueness, and that a step-up assertion is bound to the signed-in account's user handle. The COSE key is encrypted at rest. A credential deleted mid-ceremony is refused. |
| WebAuthn L3 §5.8.6 | User verification requirement. | `userVerification` follows config. Login and step-up don't silently weaken it. |

Never hand-roll JWS, TOTP or WebAuthn. The only sanctioned libraries are `firebase/php-jwt`, `pragmarx/google2fa` and `web-auth/webauthn-lib`, and the 2FA and passkey ones stay behind their feature flags.

### 4.5 HTTP semantics, caching, cookies, CSRF

| Clause | Requirement in lukk | Review checks |
|---|---|---|
| RFC 9110 §9.2.1 | Safe methods. | Nothing that changes state (rotation, logout, revoke) is reachable by GET. |
| RFC 9110 §10.2.3 | `Retry-After`. | A 429 carries delay-seconds that don't reveal whether an account exists. |
| RFC 9110 §15.5.12, §15.5.16 | 411/415. | Cookie-mode token routes refuse (415) any body a cross-site form could produce. |
| RFC 9111 §4.1, §4.2.2 | Caching. | Token and account responses are `no-store`. Nothing that varies by user can be heuristically cached. |
| RFC 6265bis §5.6, §5.7 | Cookies. | The refresh cookie is `__Host-`, `Secure`, `HttpOnly` and `SameSite=Strict`. SameSite stops a cookie being *sent*, not *set* (§5.7), so login CSRF needs the JSON / `Sec-Fetch-Site` gate. |
| Fetch Metadata (`Sec-Fetch-Site`), OWASP CSRF Cheat Sheet | Login and logout CSRF. | Only `same-origin`/`none` or `Content-Type: application/json` may set or clear the cookie, never `same-site`. In body mode, no refresh cookie is read at all. |

### 4.6 Input, text, identifiers

| Clause | Requirement in lukk | Review checks |
|---|---|---|
| RFC 3629 (UTF-8), RFC 8725 §3.7 | Valid UTF-8. | Invalid UTF-8 on any public input that reaches SQL is refused with a 422, never a 500. |
| Unicode `\p{Cc}\p{Cf}\p{Me}`, RFC 5892 (CONTEXTJ) | Identifier spelling. | Control, format and enclosing characters plus NUL are refused (`Identifier::INVISIBLE`). ZWNJ, ZWJ and U+20E3 are allowed: Persian spelling and emoji need them. The throttle fold strips them, so a respelling never gets a fresh bucket. |
| PostgreSQL / MySQL behaviour | NUL truncation, `PAD SPACE`, ignorable characters, case-insensitive collations. | Any identifier normalisation is at least as coarse as the database's own equality, or the respelling is refused outright. |

### 4.7 Privacy — GDPR

| Clause | Requirement in lukk | Review checks |
|---|---|---|
| GDPR Art. 5(1)(c) | Data minimisation. | Lockout and throttle keys hold no identifier in the clear (SHA-256 of the fold). |
| GDPR Art. 15 | Access (export). | The export discloses everything erasure deletes: sessions with `amr`/`authenticated_at`, passkeys, 2FA state, recovery codes remaining, lockouts, a pending reset. It never includes a secret, hash or token. |
| GDPR Art. 17 | Erasure. | It is atomic on every connection it writes to (nested transactions), and covers refresh tokens, passkeys, recovery codes, lockout rows and reset rows. Any parity gap with Art. 15 is a finding. |

### 4.8 Server-side request safety

| Clause | Requirement in lukk | Review checks |
|---|---|---|
| CWE-918 (SSRF) | Outbound URLs. | Nothing builds an outbound URL from request input (JWKS and `frontend_url` come from config). |
| CWE-1333 (ReDoS) | Regexes over input. | Every regex that runs on request data is linear: anchored, with no nested quantifiers on overlapping classes. |

## 5. lukk-specific review checklist

### 5.1 Config and upgrades
- Every `config('lukk…')` read has a `?? default`. `mergeConfigDeep` does nothing under `config:cache`, and `ConfigDegradationTest` scans for unguarded reads.
- Read per-guard flags (`features.abilities`, `features.gate_auth_routes`) through `Lukk::guardConfig()`, never the global block.
- A schema change ships as a publish-only migration with an `UPGRADE.md` entry. Code reading a new column must work on the old schema; probe for the column and cache the answer keyed by connection, database, `search_path` and prefix.
- Every behaviour change gets a `CHANGELOG.md` entry, plus an `UPGRADE.md` entry if a consumer must act.

### 5.2 Contracts and swap seams
- A rebound contract (`TokenIssuer`, `RefreshTokenRepository`, `LockoutRepository`, …) must not silently drop a security property:
  - `scope`/`pin` stamping lives in Actions, not the issuer;
  - `persist` force-fills;
  - the `''` versus `NULL` scope distinction round-trips.
- New contract methods go on an optional sub-interface, so existing implementations don't fatal.
- Checks that rely on stock Laravel behaviour apply only to **exactly** that class (`$x::class === EloquentUserProvider::class`), never to `instanceof`, because subclasses may decode, pepper or rehash differently.

### 5.3 Databases: always test on the real engines
- SQLite `:memory:` serialises writers and coerces types, so it hides isolation races, `22P02`/`22003` type errors, `25P02` aborted transactions, and MySQL collation behaviour. Any change to SQL, transactions or locking runs `tests/Concurrency/` on PostgreSQL **and** MySQL.
- On PostgreSQL a failed statement aborts the transaction, and its `COMMIT` silently becomes `ROLLBACK`. Never catch a query exception inside a caller's transaction without a savepoint, and never run application code under a row lock.
- Don't interpret database exceptions or read the schema on the request path to decide authentication. Both were tried and both failed review: SQL-text matching broke on Laravel's `laravel_reserved_N` aliases, and the schema read cost a catalog query per request under PHP-FPM, where statics reset on every request.

### 5.4 Timing
- A new step on the login, forgot-password or confirm path must run inside the existing `Timebox` and cost the same for a real and an unknown account (lookups, lockout reads and writes, derivations).

## 6. Deliberate deviations — not findings

Reviews must not "fix" these. If you think one is now wrong, raise it as a design question with the trade-off, not as a defect.

| Deviation | Standard departed from | Why |
|---|---|---|
| Rotation **grace window** (30 s): a replay inside it mints a sibling, not a family revoke. | RFC 9700 §4.14.2 | Strict invalidate-on-replay logs out any client with two tabs. Matches Okta's and Auth0's overlap. `RefreshFamilyForked` makes the fork visible. |
| No strict CAS on rotation. | — | Direct (non-BFF) clients can't be forced to single-flight. |
| Login throttle buckets key on the identifier **fold only**, never the resolved account. | ASVS lockout wording | Account-keyed buckets are an account-existence oracle through `Retry-After` and expiry. Look-alikes sharing a bucket is the accepted cost. |
| The `sub` precheck refuses only what's certain without I/O: NUL, a non-canonical or out-of-range integer on the stock incrementing key, a value the model's own `isValidUniqueId()` refuses for `HasUuids`/`HasUlids`. Every other shape a column can't hold is a reported 500. | RFC 8725 §3.10 (partially) | The token was signed by a trusted issuer, so it's that issuer's bug. Five more ambitious designs each produced the opposite defect. |
| HS256 by default; RS256/ES256 behind config. | — | No independent verifier exists yet. |
| The 2FA challenge token is held by the client, not server-side. WebAuthn user handles are not random. TOTP has no last-step tracking beyond the replay cache. | — | Recorded trade-offs; see the audit history in CLAUDE.md. |
| bcrypt passwords over 72 bytes answer "reset your password". | — | NIST §3.1.1.2 forbids truncation, and earlier releases stored them truncated. |

## 7. Recurring defect classes (2026-08 → 2026-10 audits)

Check every change against these. Each one shipped at least once and was caught only by a later review.

1. **A fix introduces the inverse defect** (§1.3). This was the most frequent class by far.
2. **Interpreting an exception after the fact** (SQLSTATE, message text, SQL text) hid real faults as 401s for every user.
3. **Per-request I/O hidden behind a "cached once per process" static**, which PHP-FPM resets every request.
4. **`instanceof` where the exact class was meant**: subclasses decode, pepper and rehash differently.
5. **Heuristic "is this unusable?" checks** (`Hash::info() === 'unknown'`) that a documented Laravel setting makes false. That downgraded AAL2 to AAL1.
6. **PostgreSQL-only failures**: `22P02`/`22003` on mistyped parameters, `25P02` after a caught error, a `uuid` column refusing a non-UUID `fid`, NUL truncation.
7. **MySQL-only behaviour**: concurrent first inserts deadlock (1213), `PAD SPACE`, ignorable code points in `utf8mb4_unicode_ci`.
8. **Second-boundary flakes**: tests comparing `time()` with `now()`, or a `travel()` that unfreezes the clock. Use `freezeSecond()`.
9. **Tests that pin nothing**: they pass on the parent commit. Check §1.5 every time.
10. **Docs drifting from code**: CHANGELOG and UPGRADE describing an earlier iteration of a fix.
