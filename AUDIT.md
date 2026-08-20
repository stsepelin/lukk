# Security audit register

A standing record of white-box audit findings against this package: what was fixed, and what is
knowingly open. It exists because the previous audit's findings lived only in an untracked
directory and were lost — **keep this file in git**.

Not a vulnerability disclosure channel. To report something, see the repository's security policy.

- **Last full audit:** 2026-08-20, against `main` at the 0.5.0 release candidate.
- **Method:** three parallel white-box passes (auth/rate-limiting/lockout, token crypto/rotation/
  revocation, optional features/data-at-rest), each asked to prove or disprove findings by tracing
  code and reproducing against the real route stack. Findings that could not be turned into a
  working exploit were dropped or downgraded rather than listed.
- **Standards:** RFC 7519/8725 (JWT + BCP), RFC 9068, RFC 9700, OAuth 2.1, RFC 6238/4226 (TOTP),
  W3C WebAuthn L3, NIST SP 800-63B, OWASP ASVS v4/v5, OWASP API Security Top 10.

Severities are the auditors', kept as assigned so the record isn't quietly re-graded.

## Fixed in 0.5.0

Each is pinned by a regression test; the test name is the contract.

| ID | Sev | Finding |
|---|---|---|
| `SUBJ-1` | **High** | **An attacker could clear a victim's account lockout at will.** The subject was `transliterate(lower(trim(...)))`, which is many-to-one across distinct accounts — `аdmin@` (Cyrillic а), or `ADMIN@` on any engine whose unique index compares binary — so two real accounts shared one lock row. `/auth/reset-password` releases on that subject, so whoever controlled a look-alike could lock the victim, reset their *own* password, clear the victim's lock, and repeat: `features.lockout` degraded back to the decaying throttle it exists to replace. The lockout now keys on the resolved **user id** (`id:<pk>`), falling back to the normalized identifier (`idn:<...>`) only when nothing resolves — which keeps an identifier that names no account counting, so being locked is still not an existence oracle. |
| `GUARD-1` | Medium | **Step-up confirmation was not guard-scoped.** `lukk.confirm` resolved its verifier from `lukk.set-guard`, which never runs on a consumer's own route — so an admin route verified step-up against the *users* guard's key and audience. With ids colliding across two providers (the norm for auto-increment), a confirmation earned on the users guard satisfied the admin gate; the mirror was also broken, so an admin's own confirmation could never satisfy it. Now verified against the guard that actually authenticated the request. |
| `TOTP-1` | Medium | **A junk `recovery_code` bypassed the two-factor lockout.** The recovery-code exemption was keyed on the field's *presence*, but the challenge action tries the TOTP code first — so attaching any junk recovery code skipped the §5.2.2 cap and resumed brute-forcing the 6-digit space, including against a locked account. The exemption now requires a recovery-code-**only** attempt. |
| `PK-1` | Medium | **`signCount = 0` defeated clone detection and reset the ratchet.** The regression test also required the *incoming* count to be non-zero, so a clone presenting `0` against a credential at `10` was accepted — and the `0` was written back, permanently disarming detection for the genuine authenticator too. The test is now on the stored counter alone (synced passkeys, which are `0` forever, are still never flagged) and the counter never moves backwards. |
| `CONFIRM-1` | Medium | **The extra guards' `confirm-password` had no per-user rate limit.** Only the default guard got the per-user bucket, leaving the higher-privilege audiences at 5 guesses per source `/64` per minute — thousands per minute across rotating addresses. The per-guard limiter now carries the same per-user bucket. |
| `SUBJ-2` | Low | **A transliteration blow-up could 500 the login route.** `LoginRequest` caps the identifier at 255 *characters*, but transliteration expands ~6x in bytes — 43 copies of `㈱` pass validation at 258 bytes, overflowing `lukk_lockouts.subject` and the database cache store's `key` column (MySQL 1406 / PG 22001) on an unauthenticated endpoint. Long subjects are now hashed, not truncated, so distinct identifiers can't be folded together by the fix. |
| `RELEASE-1` | Low | **`lukk:release` could not release a `two_factor` or `confirm` lock.** Those subjects are user ids recorded verbatim, but the command lower-cased everything — breaking a ULID (uppercase Crockford base32) wherever comparison is binary. Normalization is now applied only to `login`. |
| `PG-1` | Low | **The unique-violation recovery was itself a 500 on PostgreSQL.** A failed `INSERT` aborts the whole transaction (`25P02` on every later statement), so the `catch` that exists to absorb the first-failure insert race could not run. The insert is now nested, so Laravel emits a `SAVEPOINT`. |

Residual from `SUBJ-1`, accepted: the decaying **throttle** still keys on the normalized
identifier, so two look-alike accounts share a rate-limit bucket and can throttle each other. That
bucket decays in `decay_seconds` and grants no release primitive, and keying it on identity would
put a user-provider lookup in front of every login attempt — including unauthenticated floods.

Also corrected while fixing the above: the regression test for the insert race was passing without
exercising the race — its hook fired on the `hasTable` probe rather than the row lookup, so no
INSERT ever collided. Worth remembering as a shape of false assurance.

## Open

Not exploited in the deployment's default configuration, or requiring a design change. Ordered by
severity, then by how cheap the fix is.

| ID | Sev | Finding | Note |
|---|---|---|---|
| `RT-1` | Medium | **A family revoke can lose a race with a concurrent rotation on PostgreSQL.** `revokeFamily` is a set-based `UPDATE`; under READ COMMITTED its snapshot can miss a successor row inserted by an in-flight rotate transaction. The survivor keeps rotating, and once the family's denylist entry expires (`access_ttl + leeway`) its descendants authenticate again — so logout-all or a reuse kill can undo itself ~15 min later. | Reasoned from isolation semantics; **not reproduced** — needs a real PostgreSQL instance. Verify before triaging. Cheapest fix: re-check the denylist inside the rotate transaction after persisting the successor. |
| `RACE-1` | Medium | **Check-then-act between the lockout gate and the counter.** `locked()` is a plain read outside the transaction that later increments, so N concurrent requests all pass the gate and all reach `Hash::check`. Realized verifications are `max_attempts + concurrency`. Laravel's own `RateLimiter` has the same shape, so the throttle in front doesn't absorb it. | Not reproduced (needs true parallelism against MySQL/PG). Fix is to reserve the attempt before verifying rather than counting after. |
| `RT-3` | Low | `RevokeAllSessions` / `RevokeOtherSessions` DB-revoke *before* denylisting, inverting the ordering `RevokeSession` documents and obeys. A cache failure partway leaves families revoked but not denylisted, live until `access_ttl`. | Logout-all is exactly the operation performed under suspicion of compromise. |
| `DL-1` | Low | The denylist fails **closed** on a throwing cache (verified) but silently on a *cleared* one: `cache:clear` during a deploy, or memcached LRU eviction, resurrects every token revoked in the preceding `access_ttl` — including reuse-detection kills. Nothing asserts at boot that `denylist_store` is shared, durable and non-evicting. | |
| `CFG-1` | Low | An `array`/`null` cache store silently disables TOTP replay defence and the denylist, with no boot-time check. | Same class as `DL-1`; one guard closes both. |
| `PWD-1` | Low | `/auth/forgot-password` is timing-distinguishable at Laravel's default `BCRYPT_ROUNDS=12` — the broker's 200 ms `Timebox` pads a fast path but cannot claw back bcrypt's overrun. Measured disjoint distributions (unknown 205–220 ms, registered 279–335 ms): one request classifies an address. | Cost-dependent, not universal. `AttemptLogin::timingHash()` already solves this on the login path. |
| `PK-2` | Low | Passkey login skips `block_unverified_login` and `Lukk::authenticateUsing` — the documented seam for "is this account disabled?". | The three entry points should share one trait. |
| `2FA-2` | Low | `POST /auth/two-factor` on an already-confirmed account silently deactivates 2FA (nulls `two_factor_confirmed_at`, regenerates recovery codes). A user who reopens the QR and abandons it is left unprotected with no signal. | Step-up gated, so not an escalation — but a silent downgrade where `DELETE` is explicit. |
| `GUARD-2` | Low | Actions resolved from the container outside a lukk route group silently target the default guard, so a consumer's `app(RevokeAllSessions::class)(...)` on an `auth:admin` route revokes the *users* guard's families for a colliding id. The `$user->revokeAllSessions()` helper is correct. | |
| `COOKIE-1` | Low | Under multi-guard + `cookie_mode`, all guards share one `__Host-refresh` cookie name and the global `refresh_ttl`; per-guard overrides are ignored. Each login destroys the other's session. | Session destruction, not privilege crossing. |
| `VAL-1` | Low | `ResetPasswordRequest` has no `max` on `password` while login and registration cap at 255 — resetting to a longer password locks the user out of `/auth/login` with no explanation. | |
| `VAL-2` | Low | `ForgotPasswordRequest` / `ResetPasswordRequest` accept unbounded `email` and `token` on unauthenticated endpoints. | CPU only; throttled at 6/min/IP. |
| `IP-1` | Info | `Lukk::rateLimitKey()` refuses an empty *custom* key but not its own fallback: a null `$request->ip()` would bucket every caller together. No reachable path found under FPM. | One-line defensive fix. |
| `CONFIRM-2` | Info | A successful passkey login or `confirm-passkey` doesn't release the `confirm` lock, so "consecutive" is only honoured for the password authenticator. | One line, mirroring `AttemptLogin`. |
| `2FA-1` | Info | The 2FA per-account limiter key carries no guard prefix, unlike every other lukk bucket. Unreachable today (2FA mounts only on the default guard); live the moment features extend to extra guards. | |
| `2FA-3` | Info | A failed *recovery-code* attempt increments the `two_factor` counter even though the recovery path is exempt from the lock — failures against a 119-bit secret count toward a cap meant for a 6-digit one. Submitting both fields also yields two verifications per limiter slot. | |
| `EVT-1` | Info | `RefreshTokenReused` fires for `reason='revoked'` — an ordinary post-logout retry — as well as genuine reuse. Alert fatigue over the one alarm that matters. | |
| `DB-1` | Info | `passkeys.credential_id` is `VARCHAR(255)`; WebAuthn permits 1023 raw bytes (1364 base64url). An over-length ID is a 500 or a silent self-DoS. No takeover path. | |
| `DB-2` | Info | `lukk_lockouts.subject` stores plaintext identifiers, including addresses that name no account (typos, third parties probed by an attacker). Retention/PII note. | |
| `CFG-2` | Info | `recovery_codes = 0` yields **2** codes via `range(1, 0)`; negative values count up in magnitude. No clamp, unlike the lockout's. | |
| `JWKS-1` | Info | `kty` is chosen from the configured algorithm rather than the key, so a mismatched keypair publishes a structurally invalid JWK instead of failing loudly. No private material exposed. | |
| `CFG-1b` | Info | A `lukk.guards` entry named after the default guard is silently dropped while still flipping `isMultiGuard()` on — turning on guard scoping (mass logout on existing `guard IS NULL` rows) and mounting a duplicate route group. | Should throw at boot. |
| `RT-2` | Low | `POST /auth/refresh` accepts the refresh token from the **query string** (`$request->input()` unions the query for every content type), putting a 30-day opaque credential into access logs, proxy logs and `Referer`. | Fix is `post()`/`json()` rather than `input()`. |
| `RT-4` | Info | A thief who replays within `grace_seconds` gets a sibling minted, and both chains then rotate independently forever without ever tripping reuse. The accepted concurrency trade-off, but family fan-out is neither counted nor reported. | Deliberate; see `CLAUDE.md`. |

## Verified sound

Recorded so the next audit doesn't re-derive them, and so a regression is visible as a *change*:
algorithm pinning and `kid` handling (the header `alg` is never used for key selection);
cross-JWT `typ` confusion (`at+jwt` vs `+challenge`); rotation reuse-detection policy, including no
false family revoke under legitimate concurrency; revoke-then-throw staying outside the rotate
transaction with the event intact; claim validation on every request (`iss`/`aud`/`exp`/`nbf`,
deleted `sub`, cross-guard audience rejection before user resolution); no token leakage to logs or
SSR payloads, and `Cache-Control: no-store` on every token response; JWKS coordinate padding
(RFC 7518 §6.2.1.2) and public-only material; recovery-code entropy (119 bits), hashing and
transactional single-use; TOTP window, atomic replay defence and enrol-then-confirm; WebAuthn
challenge binding, origin/RP-ID validation, user-handle binding, and one user being unable to
assert another's credential; password reset not bypassing 2FA/passkeys, and its completion endpoint
having no enumeration oracle; email-verification signature binding (a link for A cannot verify B);
registration mass-assignment; middleware ordering (auth before throttle) on the confirm routes;
lockout guard scoping and the empty-subject guard; IPv6 normalization across the prefix range;
`mergeConfigDeep` backfilling a stale published config rather than degrading to `Limit(0)`.
