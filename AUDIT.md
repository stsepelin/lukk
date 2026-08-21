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
| `RACE-1` | Medium | **Concurrency could overrun the cap.** The lockout gate was a plain read outside the transaction that later counted, so N concurrent requests all passed it and all reached the credential check — realized verifications were `max_attempts + concurrency`. Attempts are now *reserved*: incremented transactionally, then compared against the cap, so only `max_attempts` requests can win a slot. Applied to login, step-up confirmation and the two-factor challenge; a success releases the reservation, so a correct credential never costs an attempt. |
| `RT-1` | Medium | **A family revoke could lose a race with a concurrent rotation.** Under READ COMMITTED the set-based `UPDATE`'s snapshot can miss a successor row inserted by an in-flight rotate, leaving a live token; once the family's denylist entry expired its descendants authenticated again, so a logout-all or reuse kill undid itself ~15 min later. Rotation now re-checks the denylist after persisting the successor. **Not reproduced — see the caveat below.** |
| `RT-2` | Low | **The refresh token was accepted from the query string.** `$request->input()` unions the query for every content type, so a 30-day opaque credential could land in access logs, proxy logs and `Referer` (RFC 9700 §4.3.2). Body only now. |
| `RT-3` | Low | **The bulk revokes denylisted after the DB write**, inverting the ordering `RevokeSession` documents. A cache failure partway left families revoked but still authenticating for up to `access_ttl` — during the one operation a user performs *because* they believe they're compromised. The denylist write moved inside the repository's transaction, before the update. |
| `EVT-1` | Info | **`RefreshTokenReused` fired for ordinary post-logout retries** (`reason='revoked'`), which apps are told to treat as theft. Alert fatigue over the one alarm that matters. Now dispatched only for genuine reuse. **Behaviour change — see UPGRADE.md.** |
| `DL-1`/`CFG-1` | Low | **An `array`/`null` cache store silently disabled revocation**, TOTP replay protection and passkey challenges: per-process storage means a revoked token stays valid on every other worker. Refused in production, where it can only be a misconfiguration. |
| `PWD-1` | Low | **`/auth/forgot-password` was timing-distinguishable.** The broker's 200 ms `Timebox` pads a fast path but cannot claw back bcrypt's overrun, so a hit and a miss had disjoint distributions and one request classified an address. The miss now burns equivalent work, as the login path already did. |
| `PK-2` | Low | **Passkey login skipped `block_unverified_login`** and never resolved the user, so a deleted account still got a refresh-token row. It now resolves through the provider and runs the same gates as the password path. |
| `2FA-2` | Low | **Re-enrolling silently disabled confirmed 2FA** — the secret was overwritten and `two_factor_confirmed_at` nulled, so a user who reopened the QR screen and wandered off was left unprotected with no signal. Refused with `409` now. **Behaviour change — see UPGRADE.md.** |
| `2FA-1` | Info | The two-factor limiter key carried no guard prefix, unlike every other lukk bucket. |
| `2FA-3` | Info | `code` and `recovery_code` are now mutually exclusive; sending both bought two verifications off one limiter slot. Recovery-code failures also no longer drive the TOTP cap — that cap exists for a 6-digit secret, and counting failures against a 119-bit one let anyone holding a challenge token lock the account without guessing a TOTP. |
| `CONFIRM-2` | Info | A successful passkey assertion now releases the `confirm` lock, so "consecutive" is honoured for passkey-primary users too. |
| `GUARD-2` | Low | **Container-resolved actions targeted the default guard.** `app(RevokeAllSessions::class)` on an `auth:admin` route revoked the *users* guard's families for a colliding id — the admin's sessions survived a "revoke everything" and an unrelated user's were destroyed. `GuardContext` now falls back to the guard that actually authenticated the request. |
| `COOKIE-1` | Low | **Every guard shared one `__Host-refresh` cookie** and the global `refresh_ttl`, so under `cookie_mode` each login destroyed the other guard's session. Name and TTL are per-guard now; the default guard keeps the unsuffixed name. **Behaviour change — see UPGRADE.md.** |
| `VAL-1` | Low | `ResetPasswordRequest` had no `max` on `password`, so a reset could set a password `/auth/login` would then refuse — locking the user out of the account they just recovered. |
| `VAL-2` | Low | `email` and `token` were unbounded on the public reset endpoints. |
| `IP-1` | Info | `rateLimitKey()` guarded a custom key against being empty but not its own fallback. |
| `DB-1` | Info | `credential_id` is a varchar(255) primary key but WebAuthn permits a 1023-byte id — a 500, or a silent truncation no later assertion could match. |
| `DB-2` | Info | The lockout table's retention/PII implication is now documented next to `features.lockout`. |
| `CFG-2` | Info | `range(1, 0)` counts down, so `recovery_codes = 0` produced two codes. Clamped. |
| `JWKS-1` | Info | `kty` came from the configured algorithm rather than the key, publishing a structurally invalid JWK on a mismatch instead of failing. |
| `CFG-1b` | Info | A `lukk.guards` entry named after the default guard was silently dropped while still enabling multi-guard mode. Throws now. |

Residual from `SUBJ-1`, accepted: the decaying **throttle** still keys on the normalized
identifier, so two look-alike accounts share a rate-limit bucket and can throttle each other. That
bucket decays in `decay_seconds` and grants no release primitive, and keying it on identity would
put a user-provider lookup in front of every login attempt — including unauthenticated floods.

Also corrected while fixing the above: the regression test for the insert race was passing without
exercising the race — its hook fired on the `hasTable` probe rather than the row lookup, so no
INSERT ever collided. Worth remembering as a shape of false assurance.

## Open

Nothing outstanding from the 2026-08-20 audit. Two accepted residuals, deliberately not "fixed":

| ID | Note |
|---|---|
| `SUBJ-1` (residual) | The decaying **throttle** still keys on the normalized identifier, so two look-alike accounts share a rate-limit bucket and can throttle each other. That bucket decays in `decay_seconds` and grants no release primitive, and keying it on identity would put a user-provider lookup in front of every login attempt, including unauthenticated floods. The persistent lockout — the part that mattered — keys on identity. |
| `RT-4` (by design) | The grace window still mints a sibling for a within-grace re-consumption, so a thief racing inside it gets a parallel chain. That is the trade that stops a multi-tab or SSR client logging itself out, and `CLAUDE.md` protects it. It is no longer *invisible*: `Events\RefreshFamilyForked` reports a family carrying more live tokens than concurrency explains. Acting on it automatically would mean revoking on suspicion — the false logout the window exists to prevent — so it stays advisory. |

### Carried caveat

`RT-1` is fixed but **was never reproduced**: it needs a live PostgreSQL instance, which this audit
did not have. The reasoning is from PG's documented READ COMMITTED semantics plus the SQL emitted,
and the fix (re-checking the denylist inside the rotate transaction) is correct on any engine. If
you ever have a PG box to hand, the repro is two connections: one `BEGIN; SELECT … FOR UPDATE`, the
other running `revokeFamily`, then insert + commit and check `revoked_at` on the new row.

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
