# Changelog

All notable changes to `lukk` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Account erasure and export (GDPR Art. 17 / Art. 15)** — a step-up-confirmed `DELETE /auth/account` that revokes every session, erases every artifact lukk owns, and deletes the user; plus `GET /auth/account/export` returning the personal data lukk holds. `features.account_deletion` defaults to **on**: erasure is a legal right, and a default of off means most installs quietly don't offer one.

  Order is the substance. The identifier is captured **first**, because one of the three lockout key spaces (`idn:<normalized identifier>`) is reachable only through it — the others are `id:<user id>` for login failures against a real account, and the bare user id for the step-up and two-factor caps. The raw identifier is never itself a key, so a sweep keyed on it matches nothing. Sessions are revoked **before** anything is deleted, denylist first, so every access token dies immediately and a failure later leaves the account unreachable rather than half-erased and still usable. Everything else runs in **one transaction**, including your `AccountDeleting` listener and the delete callback: a partial erasure is an account that cannot log in, cannot be recovered and cannot be erased again. This is deliberately the opposite trade to `RotateRefreshToken`, which keeps consumer code *out* of its transaction — erasure is rare, one-shot and irreversible, so atomicity beats lock duration. Note the revocation in step 2 is **not** rolled back by an aborting listener: the subject keeps their account and is logged out everywhere. `AccountDeleted` fires after the commit, carrying identifiers rather than the model.

  **An account is `(guard, id)`, not `id`.** Erasure and export are both guard-scoped. Providers are separate tables, so `users.id === admins.id` is the ordinary multi-guard case — an unscoped erasure destroyed an unrelated admin's refresh tokens (a permanent logout of a live account, with no `revoked_at` to explain it and no denylist entry, since revocation *was* scoped), and an unscoped export handed one subject another's session history, which Art. 15(4) forbids.

  Both routes are gated on a dedicated **`lukk.account.delete`** ability, deliberately not covered by `lukk.account`. Step-up alone does not close them to machine tokens: `RequireConfirmation` binds a confirmation to the *subject*, not to the token that earned it, so a pinned token can present one the human's session earned. And folding erasure into `lukk.account` — which already meant "manage my credentials" — would have handed every already-issued token carrying it the power to destroy the account, silently, on upgrade.

  `lukk:prune` now also removes **orphaned passkeys**, whose user no longer exists. Nothing else ever did: a passkey has no expiry, and erasure only reaches accounts deleted through lukk's own route, so a row deleted directly left the credential id, device name and last-used timestamp behind permanently. Each guard is swept against **its own** provider table, and a row lukk cannot attribute is left alone — retention is the safe direction for a daily, irreversible sweep.

  The erasure path also sweeps the **configured** password broker (`lukk.password_reset.broker`), not the default one. Laravel doesn't garbage-collect that table, so a pending reset row keeps a plaintext address of someone who asked to be forgotten for as long as the table lives; targeting the default broker missed it *and* deleted from whatever table the default pointed at, keyed on email alone, which under multi-guard is shared.

  The default disposal is **`forceDelete()`** where the model supports it. `delete()` on a `SoftDeletes` model is a silent no-op for Art. 17 — name, email, password hash and a live encrypted TOTP secret all survive — and leaves the subject neither erased nor able to return, since re-registering hits the database unique index that the `unique` validation rule's soft-delete scope ignores.

  **`Lukk::deleteUserUsing()`** replaces what happens to the user row — anonymize instead of delete, keep a tombstone, honour a retention obligation. Two things the callback then owns that deletion got for free: two-factor material lives in columns *on* the user row, so anonymizing without clearing them leaves a working authenticator attached to the erased account, and the identifier column is usually personal data in its own right.

  The export is the **auth slice only** — sessions, passkeys, whether two-factor is on — and says so loudly, because a half-answer that looks whole is worse than no endpoint. Credential material is deliberately excluded: a TOTP secret, recovery codes and refresh-token hashes are not personal data a subject benefits from receiving, they are secrets whose only use is authenticating *as* them, and Art. 15(4) says the right of access must not adversely affect others. What is included is the *fact* of each credential.

  Both routes sit behind **step-up confirmation**, never authentication alone — a stolen access token must not be enough to destroy an account or pull out everything lukk knows about someone. Step-up is not what keeps machine tokens out, though; that is `lukk.account.delete`. A pin carrying `lukk.account` can earn its *own* confirmation, and until confirmations became session-bound (below) a pin could also present one the human's browser earned.

  **`features.gate_auth_routes = false` does not reach the erasure gate.** That flag buys back pre-0.6 reach for tokens issued before abilities existed; these routes did not exist then, so honouring it would not restore an old behaviour but hand a narrow machine token an irreversible new one — a `['ci.deploy']` token could earn its own confirmation and destroy the account, arriving on upgrade with no re-consent.

- **Two-factor is guard-aware.** Three linked defects, all reachable only under [multiple guards](https://stsepelin.github.io/lukk-docs/multiple-guards) and all pinned by regression tests.

  `twoFactorRequired()` read `config('lukk.features.two_factor')` from the **global** block instead of `Lukk::guardConfig()` — the precise pattern already recorded as exploitable for `features.abilities` and `gate_auth_routes`. A guard that switched two-factor off was still challenged; one that switched it on was not.

  A secondary guard mounted `login` but **not** `two-factor-challenge`, so an enrolled account there was told to complete a challenge it had no endpoint to complete: enrolled, challenged, and bricked. The redemption route now mounts wherever `login` does, with its own per-guard throttle. Management routes (enrol, confirm, disable, recovery codes) stay on the default guard — they need step-up, and their absence locks nobody out.

  The challenge carried **no guard binding**, so isolation rested entirely on the consumer giving each guard a distinct issuer/audience/secret. Under the minimal shape — only `provider` and `path` differ — a challenge asserting "admins.1 cleared the first factor" was redeemable as "users.1 cleared the first factor". Not a second-factor bypass, since the attacker still needs that account's second factor, but a **first-factor** one: a session on a guard whose password was never presented. Challenges now carry a `gid` claim, matched strictly at redemption, with `null` still admitting a co-issuer that predates it.

- **An unreadable two-factor secret no longer bricks the account, and an empty one is refused.** `Crypt::decryptString()` throws on a stale `APP_KEY` rather than returning null, and the secret was read before either branch — so an APP_KEY rotation made every attempt a 500, and because `VerifyTwoFactorChallenge` catches only `ValidationException` the reserved lockout slot was never released. The account was locked permanently out of the recovery codes that exist for exactly that situation. The secret is now resolved lazily inside the TOTP branch, where a throw and a null mean the same thing, so a recovery-only attempt never touches it.

  `''` is refused alongside `null` in both `ChallengeTwoFactor` and `ConfirmTwoFactor`. An empty key is what a `(string) null` cast produces, and while the bundled provider rejects it, `TwoFactorProvider` is a documented swap seam — the guarantee cannot live in one implementation of it.

- **Challenge tokens require a well-formed `exp` and `jti`.** `firebase/php-jwt` does not require `exp`, so a co-issuer could mint a challenge that never expires, against "challenge single-use + short TTL". `consume()` also read `exp` *after* the second factor had verified, where an uncaught throw 500'd the request and left the challenge unburned.

- **A `guard` column on `passkeys` (breaking — see the [upgrade guide](UPGRADE.md))** — every passkey read and write is now guard-scoped, like `refresh_tokens` since 0.4.0. Without it the table was addressed by `user_id` alone, and under multi-guard the providers are separate tables where `users.id === admins.id` is the ordinary case.

  The lookup that matters is `findByCredentialId`: a WebAuthn assertion arrives with a credential id and **no user**, so that query is what decides who just authenticated — unscoped, an admin's credential resolved on the users guard. Erasing a customer also destroyed a live administrator's second factor, exporting a customer disclosed that administrator's device name and last-used timestamp (Art. 15(4)), and `lukk:prune` — scheduled **daily** — decided orphanhood against a single users table, which made every other provider's credential orphaned by construction.

  `NULL` means the single-guard default and behaves exactly as before, and `lukk:prune` checks for the column rather than assuming it — naming a column an upgraded install doesn't have would throw nightly on MySQL/PostgreSQL and, on SQLite, silently degrade to a string literal that matches nothing, leaving the new sweep inert while reporting success.

  **Backfill the column if you adopted `lukk.guards` after enabling passkeys**, or those rows become invisible to every guard: unusable, but deliberately never deleted. The reverse also needs a cleanup step and fails *open* — removing a guard leaves its stamped rows visible to the default guard, which here means its authenticator logs in as whoever holds the same id. Both directions are in the [upgrade guide](UPGRADE.md); the same asymmetry has always applied to `refresh_tokens.guard`.

  `PasskeyRepository` gains **`existsByCredentialId()`**, the one method that must stay *unscoped*: the unique index is global, so registration has to ask whether any guard holds an id before writing it. The registration challenge cache key is now guard-scoped too, so a colliding id can't let one account's in-flight ceremony clobber another's.

- **A step-up confirmation is bound to the session that earned it.** It carries the `fid` of the refresh-token family that re-verified the credential, and `RequireConfirmation` refuses one from a different family with `423` and `reason: confirmation_session_mismatch`.

  A step-up asserts "the person at this keyboard re-proved themselves just now". Bound to the subject alone it was bearer authority across **every** token that subject held — so a machine token, which can never earn a confirmation itself because the earning routes are ability-gated, could present the one the user's browser earned. Enabling two-factor, registering a passkey, regenerating recovery codes and erasing the account were all reachable that way. `fid` is stable across rotation, so refreshing mid-window keeps the confirmation valid, and BFF mode is unaffected.

  Matching is **strict**, so `null === null` still admits the co-issuer topology — a token minted by another service sharing the secret legitimately carries no `fid`, and neither does a confirmation earned by it — while an *unbound* confirmation is refused to a bearer that has one. The loose branch would only have bought a `confirm.ttl`-wide window in which the old bypass still worked.

- **Abilities / scopes** — coarse, stateless authorization carried in the access token. `Lukk::abilitiesUsing(fn ($userId, $context) => ['orders.read', 'orders.*'])` mints a `scope` claim; `lukk.ability:a,b` gates a route on **any** of them and `lukk.abilities:a,b` on **all** (Sanctum's split, so the semantics are the ones people already expect); `$user->tokenCan('orders.read')` via the `HasTokenAbilities` trait.

  The wire format is the registered `scope` claim, space-delimited (RFC 6749 §3.3, RFC 9068 §2.2.3), so an API gateway or a non-lukk verifier can read it without knowing about lukk. `*` grants everything and `orders.*` grants the namespace — but a wildcard only ever appears in the *grant*, never in the check, so a caller can't widen their own question by asking `tokenCan('orders.*')`. Grants are validated against the RFC's `scope-token` charset and a malformed one **throws**: the claim is space-delimited, so `['orders.read admin']` would otherwise parse back as two abilities and hand out an `admin` nobody issued — reachable the moment ability names come from data.

  **Deny by default, and inert until configured.** Without `abilitiesUsing` no claim is minted at all and tokens stay byte-identical to 0.5.0. Once it's set, a token with no `scope` grants nothing — because adding `lukk.ability:admin` to a route while forgetting to configure abilities should fail loudly, not wave everyone through. `scope` also becomes **reserved**: `tokenClaimsUsing` can no longer set it, in either direction — it can't forge a grant, and an empty grant can now *erase* one it set (`abilitiesUsing` returning `[]` for a suspended user must not still mint `admin.*`).

  The second argument is a `TokenContext` carrying the **guard** and the session's **family id**. A multi-guard install serves different audiences often enough that `['*']` for a customer token and `['*']` for an admin one are not the same grant; an object rather than more positional parameters means the next field added won't break closures already written.

  By default abilities are **re-derived on every mint**, not frozen at login, so revoking one takes effect within `access_ttl` instead of lasting the life of the refresh token. A session that must instead carry a **fixed** grant — a personal access token, an impersonation session capped below the target user — passes its abilities to `StartSession`, which stores them on the family row (new nullable `scope` column, see the [upgrade guide](UPGRADE.md)) and replays them through every rotation. `NULL` means derived; a value means pinned.

  `$user->tokenCan()` reads the token the guard verified onto the **request**, not state on the model. Sanctum's model-state equivalent has two failure modes this avoids: a model the guard never touched (`$order->user`, a fresh `find()`) silently denies what the token was actually granted, and a model that outlives its request answers from the *previous* token's grant.

  A gate reached with no credential at all answers **401**, not 403 — a 403 tells a client "you are known and refused", so it stops retrying and never learns it just needs to log in. Insufficient scope answers 403 with `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"` (RFC 6750 §3.1), naming what would have sufficed. The gates are registered **after** `Authenticate` in the kernel's middleware priority, so `['lukk.ability:x', 'auth:api']` and the reverse order behave identically.

  `Http\Resources\UserResource` publishes the token's `abilities`, which is the only channel a BFF-mode client has — it never sees the access token that carries the claim. **Absent, not empty**, when abilities aren't in play: `[]` means "in use, granted nothing" (hide the UI) while an absent key means "this server doesn't use abilities" (show it), so an install that upgrades without opting in doesn't find its UI blanked. Only emitted for the token's own subject, so a user list doesn't stamp every row with the reader's grant.

  `Lukk::actingAs($user, $guard, $abilities)` stands in for a token in tests, and **throws outside the test environment**. The container binding it uses is not the safety net it looks like: `forgetScopedInstances()` drops the resolved instance but leaves the binding — a closure holding the token by value — registered, so on a long-lived worker the next request re-resolves the same token. Rather than ship a mechanism whose only safe use is the one nobody enforces, it refuses to run in production; grant abilities there by minting a token that carries them.

  A grant pinned to **nothing** stays nothing. `toScope()` collapses an empty grant to `null` and `null` on the column means "derive", so a zero-scope token — a capped impersonation session, a PAT granted nothing — would have widened to the subject's *full* grant on its first refresh. The column stores `''` for a pinned-empty grant and keeps the two states apart.

  **Name abilities after resources, not after facts about a person.** An ability name travels in the `scope` claim past every proxy and gateway, is published on the user resource, and appears as a literal string in your JavaScript bundle. `hiv_clinic.records.read` is a special-category disclosure at each hop; `clinic_a.records.read` is not. lukk validates the *syntax* of a name (RFC 6749) and can say nothing about its meaning.

  A new `features.abilities` flag (default off) exists for one case: grants that come **only** from an explicit `StartSession` pin, with no `abilitiesUsing` callback. Configuring the callback turns the feature on by itself, so most installs never touch it. Without the flag lukk can't distinguish a token pinned to *nothing* from a server that doesn't use abilities — and the client would then render the full privileged UI for the most restricted token you can issue.

  **`Events\TokenAbilityDenied`** fires when a verified token is refused a route for its scope. lukk announces every other security transition it owns, and a token probing for what it can still reach looks exactly like a run of these — without it a deployment has no lukk-side signal at all. Deliberately an event and not a log line: ability names travel widely enough already. The payload carries the *route's* requirement, never the caller's granted list, since a queued listener would serialize it.

  **`abilitiesUsing` is resolved before the refresh transaction opens**, not inside it. The callback is application code documented as hitting a permission store, and running it under `FOR UPDATE` made lukk's correctness depend on someone else's query: a slow lookup extended the lock on every refresh, taking locks in the opposite order deadlocked against it, and on PostgreSQL a callback that swallowed its own SQL error left the transaction aborted — where `COMMIT` becomes a silent `ROLLBACK`, so lukk handed back a valid access token whose successor row was never written and the client discovered it was logged out one refresh later. Nothing but lukk's own statements and pure crypto run inside the lock now, pinned by two PostgreSQL tests in `tests/Concurrency/`.

  **`Lukk::assertGuardsIsolated()` now refuses to boot a `lukk-jwt` guard that has no `lukk.guards` block of its own.** Pre-existing since multi-guard shipped in 0.4.0: the check keyed on `config('lukk.guards')`, so a second guard declared only in `config/auth.php` skipped it entirely — and `guardConfig()` then deep-merged nothing over the top-level block, handing that guard the default guard's secret *and audience*. Audience is the control that stops one guard's token verifying on another, so a customer's access token authenticated as whatever the second guard's provider returned for the same id: a different user, in a different table, HTTP 200, no boot error and nothing in the log.

  **lukk's own `DELETE /auth/sessions` and `/auth/sessions/others` are gated on `lukk.sessions`.** A token pinned to `['ci.deploy']` — the most restricted thing the API can issue, refused by every gated route in the application — could still revoke every *other* session and log the account out everywhere, because lukk's own routes were gated on authentication alone. Only a **pinned** grant is gated, marked by a new `pin` claim stamped just on those tokens: a derived grant is a live human login and keeps managing its own sessions, so nothing changes for an existing install and nobody has to discover a new ability name. `logout` and `refresh` are deliberately not gated — they act on the calling session alone, and a personal access token has to be able to end and renew itself. Turn the whole thing off with `features.gate_auth_routes`.

  **`tokenClaimsUsing` is resolved before the refresh transaction too.** Moving the mint inside the transaction (above) left the claims hook under the row lock, since the issuer was the one resolving it — the same consumer callback, the same permission-store read, the same three hazards. Both hooks now run ahead of the transaction, behind the same reject short-circuit, so neither is asked about a token lukk is going to refuse and neither can throw early enough to pre-empt reuse detection. The issuer no longer resolves either: it stamps what the Action hands it. Per-login claims still beat the hook's, and standard claims still beat both.

  **`features.abilities` and `features.gate_auth_routes` are read through the active guard's config**, not the global block. `guardConfig()` deep-merges `lukk.guards.{name}` over the top level, so a deployment can switch a feature on for one guard — and both flags ignored that while failing *open*: the claims hook could become the authorization layer on the second guard, and a guard could not switch the session gate on for itself.

  **The pinned-token boundary covers account-security operations too**, via a second ability `lukk.account`: both step-up routes (`confirm-password` *and* `confirm-passkey` — gating one and not the other would make it decorative) and `POST /auth/password`. Step-up is the gateway to everything that takes an account over permanently — enrolling a passkey, disabling two-factor, regenerating recovery codes — and changing the password both rotates the credential and sweeps every other session. All of it needs the password, so a pinned token could never do it silently; but "a machine token must not log the account out everywhere" and "a machine token may enrol a permanent authenticator" cannot both be the rule.

  **Pinned-ness is confirmed against the database when the `pin` claim is absent.** The claim is stamped by `TokenIssuer`, a documented swap seam, so an implementation that forwards `$abilities` but forgets `TokenContext::$pinned` produced a genuinely pinned token that lukk's own gates waved through — and note the asymmetry that made this worth a round trip: the `scope` half of the same seam fails *closed* and loudly, this half failed *open* and silently. Costs one indexed lookup, only when the claim is absent, on routes that already revoke sessions or verify a password.

  Refresh-token rows are written with `forceFill`, not mass assignment. `Lukk::useRefreshTokenModel()` is a documented seam, and a subclass declaring `$fillable` silently dropped `scope` — turning a token pinned to one ability into the subject's *full* derived grant on its first refresh, session management included, because `familyIsPinned()` reads the same column that was never written and so collapsed with it. `StartSession` additionally refuses to hand back a pinned session whose pin didn't reach storage.

  Scope is deliberately coarse: it says what a *token* may do, never which *records* it may touch. Per-object authorization stays your Policies and Gates (OWASP API1 — BOLA).

## [0.5.0] - 2026-08-21

### Added

- **Change password while signed in (`POST /auth/password`)** — the counterpart to the forgot-password flow, without the email round-trip. Re-verifies the current password, applies `Password::defaults()` to the new one, revokes every **other** session, and fires `Events\PasswordChanged`.

  Asking for the current password is the whole security story: a stolen access token alone must not be enough to take an account over permanently, which is exactly what changing the password would do. Because it checks the same secret as login and step-up, it runs on the **same** budget — the `lukk-confirm` throttle and, with `features.lockout` on, the `confirm` counter. Two independent allowances for guessing one password is just a larger allowance. A success clears **both** the `confirm` and `login` counters, since the failures they hold were against a password that no longer exists — otherwise a user who was being brute-forced, noticed, and changed their password stayed locked out of login on every other device.

  Other sessions die; the one it was done from survives. (A token carrying no `fid` — one minted by a co-issuer sharing the secret — identifies no session here to preserve, so every session is revoked rather than none.) Changing a password is what someone does when they think another party is in the account, so leaving those sessions alive would defeat the point — but logging the user out of the tab they just did it in is a bad answer to a good instinct. The session to keep is read from the caller's own verified token, so it can't be pointed at someone else's to spare it from the sweep.

  On by default (`features.change_password`), like `logout_all`: it needs no configuration, and refusing a signed-in user the ability to change their own password is not a sensible default. Turn it off where passwords live in an identity provider.

- **Account lockout (`features.lockout`, opt-in, off by default)** — an absolute cap on *consecutive* failed authentication attempts, satisfying **NIST SP 800-63B §5.2.2** ("the verifier SHALL limit consecutive failed authentication attempts on a single account to no more than 100"). The existing throttles are decaying windows: they bound a *rate*, not a *run*, so lifetime guesses were unbounded — roughly 7,200/day against a 6-digit TOTP code. Covers both password login (keyed on the normalized identifier) and the two-factor challenge (keyed on the user), each with its own counter and guard-scoped, so burning one doesn't spend the other's budget.

  Counters live in a new `lukk_lockouts` table (publish `lukk-lockout-migrations`) because "consecutive" can't be expressed by a cache entry that expires — and a cache flush would silently release every lock. `Lockout` storage sits behind a `LockoutRepository` contract, so it's swappable like `RefreshTokenRepository`.

  **A hard lockout is also a denial-of-service primitive** — anyone who knows an address can burn its budget deliberately — which is why it ships off, and why release has five paths: any successful authentication clears the run (that's what "consecutive" means), a **password reset** clears it (proving control of the address is stronger evidence than the password, so this is the self-service way out), `php artisan lukk:release <subject>` for operators, the repository API for your own code, and an optional `lockout.release_after` that auto-lifts and bounds the denial. Every path fires `AccountReleased`, so an audit log sees the unlock and not just the lock. A locked account answers **423** rather than 429, because with manual-only release "retry later" would be untrue. `AccountLocked` fires once on the transition — a locked-out user gets no other signal.

Two honest caveats. Setting `release_after` **trades the strict reading**: a run broken by time rather than by a success is no longer "consecutive", so 100/3600s is a 100-per-hour cap — which is exactly OWASP ASVS V2.2.1, and better than the package's current ~1,200/hour, but not §5.2.2's lifetime bound. And a recovery code is deliberately **not** gated by a two-factor lock: at ~119 bits it isn't brute-forceable, and gating it would strand a user whose second factor an attacker burned on purpose.

- **`Lukk::rateLimitKeyUsing()`** — replace the identity every lukk throttle buckets on. The default is the request IP; override it when the source address isn't the right bucket for your deployment (a shared API gateway, a tenant, a CDN's own visitor token).

### Changed

- **Every throttle now collapses an IPv6 caller to their `/64`.** A subscriber is typically handed a whole `/64`, so keying on the full address let one visitor mint effectively unlimited buckets and walk through every per-IP limit. IPv4 is unchanged, and an IPv4-mapped address (`::ffff:1.2.3.4`) is unwrapped to its IPv4 form rather than collapsing every mapped address into one shared `::/64` bucket — the same unwrapping applies to NAT64's `64:ff9b::/96`, so an IPv6-only client population behind a translation gateway isn't bucketed as one caller. This only starts to matter once the address is genuinely the visitor's — behind a BFF it is the proxy until the deployment forwards the real client — which is exactly when per-IP limits stop being a single shared bucket and start needing to hold.
- **The authenticated email-verification resend gained a second, per-user limit** alongside the per-IP one. Rotating IPs is cheap once per-IP buckets are genuinely per-visitor, so a single session could otherwise resend without limit. It reuses the endpoint's existing `max_attempts`/`decay_seconds` (no new configuration; Laravel applies every returned limit and the tighter wins) and is guard-scoped, resolving the user from lukk's own guard — the same limiter also guards the unauthenticated signed verify route, where the app's default guard could otherwise share a bucket with a colliding id from an unrelated provider. Registration deliberately did **not** get the same treatment: a duplicate signup is a `422` from the `unique` rule and sends no mail, so an identity bucket there would bound nothing while handing anyone a remote, IP-independent way to deny a chosen address the ability to register.
- **`rate_limits.ipv6_prefix`** (env `LUKK_RATE_LIMIT_IPV6_PREFIX`, default `64`) tunes the IPv6 mask. `64` suits residential and mobile networks; lower it if your attackers hold larger delegations, or raise it toward `128` if your users share a `/64` — an office or campus LAN does.

### Security

- **A full audit pass closed 24 findings.** Three parallel white-box reviews against the release candidate (auth/rate-limiting/lockout, token crypto/rotation/revocation, optional features/data-at-rest), each asked to prove findings by reproducing them. Every finding is fixed and pinned by a regression test; the two accepted trade-offs are documented under [Known limitations](https://stsepelin.github.io/lukk-docs/security#known-limitations). Highlights beyond the step-up work below:

  - **Concurrency could overrun the lockout cap** (`RACE-1`). The gate was a plain read outside the transaction that later counted, so N concurrent requests all passed it and all reached the credential check — realized verifications were `max_attempts + concurrency`. Attempts are now reserved: incremented transactionally, then compared against the cap.
  - **A family revoke could lose a race with a concurrent rotation** (`RT-1`), leaving a live token behind so that a logout-all or a reuse kill undid itself once the denylist entry expired. Rotation re-checks the denylist after persisting the successor. Reasoned from PostgreSQL's READ COMMITTED semantics; **not reproduced** — the caveat is recorded rather than dropped.
  - **The refresh token was accepted from the query string** (`RT-2`), putting a 30-day opaque credential into access logs and `Referer` headers (RFC 9700 §4.3.2).
  - **The bulk revokes denylisted after the DB write** (`RT-3`), inverting the ordering `RevokeSession` documents — a cache failure partway left families revoked but still authenticating.
  - **`/auth/forgot-password` was timing-distinguishable** (`PWD-1`): the broker's `Timebox` pads a fast path but cannot claw back bcrypt's overrun, so one request classified an address.
  - **Passkey login skipped `block_unverified_login`** and never resolved the user (`PK-2`).
  - **Every guard shared one refresh cookie** (`COOKIE-1`) and **container-resolved actions targeted the default guard** (`GUARD-2`).
  - Plus bounds on the reset endpoints, a clamp on `recovery_codes`, a guard against an `array` denylist store in production, and a loud failure for a `lukk.guards` entry named after the default guard.

- **`Events\RefreshFamilyForked`** — the grace window mints a sibling rather than revoking, which is what stops a multi-tab or SSR client logging itself out; the cost is that a thief racing inside the window gets a parallel chain that never trips reuse detection. That was previously invisible. Advisory by design — acting on it automatically would mean revoking on suspicion.

- **The account lockout keys on the resolved user, not on the submitted identifier.** `transliterate(lower(trim(...)))` is many-to-one across distinct accounts — `аdmin@example.com` with a Cyrillic а, or plain `ADMIN@example.com` on any engine whose unique index compares binary — so two real accounts shared one counter. Because a password reset releases on that subject, anyone who controlled a look-alike account could lock the victim, reset their own password to clear the shared lock, and repeat indefinitely; the §5.2.2 cap collapsed back to the decaying throttle it exists to replace, and two legitimate look-alike accounts locked each other out as collateral. Subjects are now `id:<primary key>` when the identifier names an account and `idn:<normalized>` when it doesn't — the fallback matters, because an identifier that names no account must still accumulate a counter or `423`-vs-`422` would answer "does this account exist?" for free. `lukk:release` resolves a pasted address the same way, as written and then normalized, so the operator flow is unchanged.

- **Step-up confirmation is now guard-scoped.** `lukk.confirm` resolved its verifier from the `lukk.set-guard` middleware, which only runs inside lukk's own route groups — never on a consumer's own `['auth:admin', 'lukk.confirm']` route. The guard silently fell back to the default, so an admin route verified step-up against the **users** guard's key and audience. With user ids colliding across two providers (the norm for auto-increment), a confirmation earned on the users guard satisfied the admin gate — defeating the control that exists to limit what a stolen access token can do. The mirror was broken too: an admin's own confirmation, minted at `admin/auth/confirm-password`, could never satisfy the gate. It now verifies against the guard that actually authenticated the request.

- **A junk `recovery_code` no longer bypasses the two-factor lockout.** The recovery-code exemption was keyed on the field being *present*, but the challenge action checks the TOTP code first — so attaching any junk recovery code skipped the §5.2.2 cap and carried on brute-forcing the 6-digit space, including against an already-locked account. The exemption now requires a recovery-code-**only** attempt; a recovery code on its own still releases the lock, which was the point of the exemption.

- **A passkey `signCount` of 0 no longer defeats clone detection.** The regression check also required the *incoming* counter to be non-zero, so a clone presenting `0` against a credential that had reached `10` was accepted — a textbook WebAuthn L3 §6.1.1 regression — and the `0` was then written back, resetting the ratchet so the genuine authenticator could never trip it either. The test is now on the stored counter alone, and the counter never moves backwards. Synced passkeys are unaffected: their stored count is `0` forever, which is what keeps them from ever being flagged.

- **Bounded the lockout subject in bytes.** `LoginRequest` caps the identifier at 255 *characters*, but transliteration expands up to ~6x — 43 copies of `㈱` pass validation and arrive as 258 bytes, overflowing `lukk_lockouts.subject` and, on Laravel's default `database` cache store, the `cache.key` column: MySQL `1406` / PostgreSQL `22001`, surfacing as a 500 on the unauthenticated `/auth/login`. Long subjects are hashed rather than truncated, so two distinct identifiers can't be folded into one shared bucket by the fix itself.

- **Step-up confirmation is throttled and lockable.** `POST /auth/confirm-password` and `/auth/confirm-passkey` had **no rate limit at all** — only the guard. Since password confirmation re-verifies the *same* secret the login route throttles two ways, anyone already holding an access token (a stolen one, an XSS'd one, a shared device) had an unmetered password oracle sitting behind the sudo gate. Both routes now run a `lukk-confirm` limiter (`rate_limits.confirm`, default 5/60s, plus `lukk-{guard}-confirm` for the additional guards), keyed on **both** the user and the IP — the per-user bucket is the load-bearing one, because a caller with a stolen token is a single identity behind however many addresses they care to use.

  With `features.lockout` on, a run of failed password confirmations also counts toward the **NIST SP 800-63B §5.2.2** cap under a new `confirm` purpose, keyed on the user id (the caller is already authenticated, so unlike the login lock there is a resolved account and no enumeration concern). Two escapes beyond `release_after` and `php artisan lukk:release <id> --purpose=confirm`: a **successful login** clears it — proof of the same password, and something an attacker holding only a token cannot produce — and so does a **password reset**, after which the counted failures are against a password that no longer exists. `confirm-passkey` is metered but deliberately **not** locked: an assertion is a signature, not a guessable secret, so the throttle there is DoS protection rather than brute-force defence.

### Fixed

- **`php artisan lukk:release` could not release a `two_factor` or `confirm` lock.** Those subjects are user ids, recorded verbatim, but the command lower-cased every subject — which breaks a ULID (uppercase Crockford base32) on every engine that compares binary (PostgreSQL, SQLite). The documented operator escape hatch silently released nothing. Normalization now applies only to `login`, whose subject really is a normalized identifier.
- **The lockout's insert-race recovery was itself a 500 on PostgreSQL.** A failed `INSERT` aborts the entire transaction there (`25P02` on every subsequent statement), so the `catch` that exists to absorb two concurrent first-failures could not run. The insert is now nested, so Laravel emits a `SAVEPOINT` and the rollback stays local.
- **`POST /auth/register` bounds the identifier length** (`max:255`, matching `name` and `password`). `email` + `unique` against an unbounded string was avoidable work for an anonymous caller (ASVS V2.1).

## [0.4.0] - 2026-07-07

### Added

- **Multiple guards** (multi-audience isolation). Declare a second isolated audience — an admin API alongside the users API — under `config('lukk.guards')` plus a `lukk-jwt` guard in `config/auth.php` (whose `provider` lukk reuses). Each guard carries its own cryptographic token identity: its own **`audience`** (required, distinct) and optionally its own `secret`/keys/`issuer`/ttls. A token minted for one guard is rejected by another on the audience check (and signature, when keys differ) — **before any user is resolved**, so it can never resolve `User::find($sub)` on the wrong guard (RFC 8725 §3.9 / OWASP ASVS 5.0 §9.2.3–9.2.4). Refresh-token families and logout-all are scoped by a nullable `guard` column, so revoking one guard's sessions can't touch another's even when user ids collide (`users.id == admins.id`). Routes auto-mount per guard under a per-guard `path` and optional **`domain`** (subdomain isolation). lukk **refuses to boot** unless every guard declares a distinct, non-empty audience and mounts at a distinct path/domain, and every extra guard is declared in `config/auth.php`. `php artisan lukk:secret --guard=admin` writes `LUKK_ADMIN_SECRET`; `HasRefreshTokens::lukkGuard()` binds a model (e.g. `Admin`) to its guard. An app with no `lukk.guards` behaves exactly as before.
- **Registration** (opt-in via `features.registration`). A first-party `POST /auth/register` that mirrors login: it creates the user, fires `Illuminate\Auth\Events\Registered` (so the email-verification listener sends the link), and returns the same token pair a login yields (BFF or cookie mode) — or a 2FA challenge if the new user is already enrolled, or a `201` no-session shape when the account can't log in yet. The built-in default create works with the **stock Laravel `users` shape out of the box** (`name` + the identifier + a hashed `password`). Fully customizable: `Lukk::registerUsing()` owns user creation (closure or invokable class-string), `Lukk::registerValidation()` (or rebinding `RegisterRequest`) owns the fields/rules, and `RegisterResponse` is rebindable like the other response contracts. `registration.login` (default true) toggles auto-login vs. create-only (`201`, sign in separately). Per-IP throttled (`lukk-register`); a duplicate identifier is a `422` (the only enumeration a registration form inherently has). Backward compatible — off by default.
- **Configurable login identifier** (`lukk.username`, default `email`). Fortify-style: set it to `username` (or any unique column) and both login and registration authenticate by that column instead of email — the login request field, the constant-time credential lookup, the per-account throttle bucket, and the registration validation/create all follow it. Defaults to `email`, so existing behavior is unchanged.

### Changed

- **`refresh_tokens` schema: added a nullable `guard` column** (for multi-guard family isolation; it stays null and unused under a single guard). ⚠️ **Pre-1.0 schema change** — because lukk is `0.x` with no stable installs, this was folded into the existing `create_refresh_tokens_table` migration rather than shipped as a separate one. **Fresh installs are unaffected** (publishing `lukk-migrations` creates the column). A pre-release install that already ran the old migration must add the column manually — `ALTER TABLE refresh_tokens ADD COLUMN guard VARCHAR(255) NULL` — or drop and re-run the migration. See the [UPGRADE guide](UPGRADE.md#upgrading-to-040-from-03x). Future schema changes (post-1.0) will ship as additive migrations.

## [0.3.0] - 2026-07-02

### Added

- **Password reset** (opt-in via `features.password_reset`), built on Laravel's password broker. `POST /auth/forgot-password` emails a reset link pointing at your SPA (`password_reset.frontend_url?token=…&email=…`) and always returns a generic `200` (no user enumeration, throttled `lukk-password-reset`); `POST /auth/reset-password` consumes the token, sets the new password, fires `Illuminate\Auth\Events\PasswordReset`, and — unless `password_reset.revoke_sessions` is false — **revokes every existing session** (refresh families + denylist) so a session that predates the reset can't survive it. Relies on the framework-default `password_reset_tokens` table + an `auth.passwords` broker (`password_reset.broker` selects a non-default one; no lukk migration). Both endpoints are enumeration-safe — reset returns one generic `422` for every failure. See the [password-reset docs](https://stsepelin.github.io/lukk-docs/password-reset).

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

[Unreleased]: https://github.com/stsepelin/lukk/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/stsepelin/lukk/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/stsepelin/lukk/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/stsepelin/lukk/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/stsepelin/lukk/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/stsepelin/lukk/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/stsepelin/lukk/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/stsepelin/lukk/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/stsepelin/lukk/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/stsepelin/lukk/releases/tag/v0.1.0
