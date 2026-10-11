# Upgrade Guide

This guide lists every change that **requires action on upgrade** — schema changes,
default-behavior changes, and anything that can surprise an existing install. For the
full list of what's new (features, fixes), read the [CHANGELOG](CHANGELOG.md); this file
is deliberately only the "you may need to do something" subset.

**lukk is pre-1.0 (`0.x`).** Per [SemVer §4](https://semver.org/#spec-item-4), a **minor**
bump (`0.x.0`) may carry a breaking change; a **patch** bump (`0.x.y`) never does. Each entry
below is tagged **High / Medium / Low impact** so you can scan for what applies to you.
Nothing here is applied automatically — lukk's migrations are **publish-only** and its
behavior is **config-gated**, so an upgrade only affects you where you've opted in.

Before upgrading: pin an exact version, read the entries at or below your target, then run
your test suite. The 1.0 release will mark API/schema stability and this cadence ends.

**Impact key** — _High_: action required or an install will break/behave wrong. _Medium_:
action required only if you use the named feature. _Low_: informational; a behavior changed
but the default is safe.

---

## Upgrading to 0.7.0 from 0.6.x (unreleased)

### The default guard must use `lukk.user_provider`

**High impact — only if `auth.guards.<default>.provider` (or, naming none, `auth.defaults.provider`)
differs from `lukk.user_provider`.** Boot now throws, naming both. Sign-in checked passwords against
`lukk.user_provider` while the guard resolved tokens through the other provider, so a password from one
table signed in as the row with the same id in the other. Point both at the same provider. Nothing
changes for the default configuration (`users` on both sides), a guard naming no provider with
`auth.defaults.provider` unset, or a default guard that is not `lukk-jwt` — nor for two provider names
over the same users: the same `model` under the `eloquent` driver, or the same `table` and `connection`
under `database`. A provider with any other driver boots only if its whole `auth.providers` entry is
identical to the other's.

### Identifiers with invisible characters are refused

**Low impact — check if your identifiers can contain them.** Sign-in, registration, forgot- and
reset-password answer 422 for an identifier carrying a control character (NUL, C0, C1), a format
character (zero-width space, word joiner, soft hyphen, bidi controls), an enclosing mark, U+034F, or
whitespace other than the ASCII space; registration's `name` refuses NUL. Combining marks, accented
letters, U+200C ZERO WIDTH NON-JOINER and U+200D ZERO WIDTH JOINER (Persian spelling, emoji ZWJ
sequences) and U+20E3 COMBINING ENCLOSING KEYCAP are accepted. An account whose STORED identifier
contains a refused character can no longer type it to sign in — find them before upgrading. The
authoritative check is the pattern lukk validates with, run in PHP (swap in your model and
`lukk.username` column):

```php
use Illuminate\Support\Facades\DB;
use Lukk\Support\Identifier;

DB::table('users')->select(['id', 'email'])->lazyById()->each(function ($row) {
    if (preg_match(Identifier::INVISIBLE, (string) $row->email) === 1) {
        echo $row->id, PHP_EOL;
    }
});
```

In SQL, these match the same set as PCRE2 10.49's Unicode tables (Unicode 17; checked on PostgreSQL 17 and MySQL 8.4) — a later Unicode version can add
format characters that only the PHP scan sees. PostgreSQL (`standard_conforming_strings` on, the default):

```sql
SELECT id, email FROM users WHERE email ~ '[\u0001-\u001F\u007F-\u00A0\u00AD\u034F\u0488-\u0489\u0600-\u0605\u061C\u06DD\u070F\u0890-\u0891\u08E2\u1680\u180E\u1ABE\u2000-\u200B\u200E-\u200F\u2028-\u202F\u205F-\u2064\u2066-\u206F\u20DD-\u20E0\u20E2\u20E4\u3000\uA670-\uA672\uFEFF\uFFF9-\uFFFB\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0001\U000E0020-\U000E007F]';
```

MySQL 8.0.4+ (ICU regular expressions; with `NO_BACKSLASH_ESCAPES` in `sql_mode` the doubled backslashes
reach the regex as written and it fails with error 3697 — run it in a session without that mode, or halve them):

```sql
SELECT id, email FROM users WHERE email REGEXP '[\\x{0000}-\\x{001F}\\x{007F}-\\x{00A0}\\x{00AD}\\x{034F}\\x{0488}-\\x{0489}\\x{0600}-\\x{0605}\\x{061C}\\x{06DD}\\x{070F}\\x{0890}-\\x{0891}\\x{08E2}\\x{1680}\\x{180E}\\x{1ABE}\\x{2000}-\\x{200B}\\x{200E}-\\x{200F}\\x{2028}-\\x{202F}\\x{205F}-\\x{2064}\\x{2066}-\\x{206F}\\x{20DD}-\\x{20E0}\\x{20E2}\\x{20E4}\\x{3000}\\x{A670}-\\x{A672}\\x{FEFF}\\x{FFF9}-\\x{FFFB}\\x{110BD}\\x{110CD}\\x{13430}-\\x{1343F}\\x{1BCA0}-\\x{1BCA3}\\x{1D173}-\\x{1D17A}\\x{E0001}\\x{E0020}-\\x{E007F}]';
```

The login-throttle fold also changed for identifiers containing such characters (or combining marks,
ZWNJ, ZWJ or the keycap), so their buckets restart once; a held `idn:` lockout row for such an identifier
is no longer reached by it. On PostgreSQL two accounts may differ only by a ZWNJ, ZWJ or keycap (`ab` and
`a\u{200D}b`); the throttle folds them onto one bucket, as it does accounts differing only in case or
accents. MySQL's collation already treats them as one value, so `unique` refuses the second.

### `auth_time` is stored with the session

**Low impact.** The sign-in time now travels in the `refresh_tokens.amr` column, beside `amr`
(`{"amr":[…],"auth_time":…}`), instead of being re-derived on rotation as `expires_at − refresh_ttl` —
lowering `refresh_ttl` made old multi-factor sign-ins look recent. A session stored before this has no
stored sign-in time, so its tokens carry no `auth_time` after its next refresh, and a password step-up
that leaned on a recent multi-factor sign-in asks for a fresh one (or a passkey). **If you implement `RefreshTokenRepository`**, treat the
`$amr` argument of `persist()` as opaque: store it and hand it back on `RefreshTokenRecord::$amr`
unchanged (the signature is unchanged). One that drops it keeps working, without `amr` or `auth_time`
after the first refresh.

### Locking happens after the failed check (`ReservesLockoutAttempts`)

**Low impact — only if you implement `LockoutRepository` yourself, or listen for lockout events.** The
actions still reserve an attempt before verifying it, but the lock and `AccountLocked` now land only when
the credential was wrong, so the attempt that reaches the cap with the right credential no longer fires
`AccountLocked` and `AccountReleased`. Implement the optional `Lukk\Contracts\ReservesLockoutAttempts`
(`reserve()`, `lockIfSpent()`) to get this; a repository implementing only `LockoutRepository` keeps
locking at the reservation through `recordFailure()`.

### Refresh-token model events no longer fire for lukk's writes

**Low impact — only if you observe a `useRefreshTokenModel` subclass.** `persist()` now saves quietly:
it runs under the rotation's row lock, where an observer serialised refreshes and, on PostgreSQL, could
silently roll back the rotation. `creating`/`created`/`saving`/`saved` no longer fire for refresh tokens
lukk stores, and a listener can no longer cancel one. Audit sessions from lukk's events instead
(`RefreshTokenReused`, `SessionUnclaimed`, and your own login/logout listeners).

**A column you fill from `creating` is no longer filled** — a multi-tenancy `BelongsToTenant` trait
stamping `tenant_id`, for one; on a `NOT NULL` column every sign-in and refresh then fails. Fill it as the
model is built instead: an `$attributes` default on your `useRefreshTokenModel` subclass, or the trait's
`initialize{TraitName}()` method, which Eloquent calls from the constructor without dispatching an event
(`public function initializeBelongsToTenant(): void { $this->tenant_id ??= tenant()->id; }`). Overriding
`persist()` in a subclass of `DatabaseRefreshTokenRepository` works too. Either way the code runs under
the rotation's row lock: read a value already in memory, never query.

### Smaller changes you might notice

**Low impact.**

- `Lukk\Events\RecoveryCodeUsed` fires when a recovery code is spent; listen for it to notify the user
  and prompt new codes (NIST SP 800-63B-4 §4.2).
- The account export gains `password_reset`, `two_factor.pending`, `two_factor.recovery_codes_remaining`
  and per-session `amr` / `authenticated_at`.
- With `Lukk::authenticateUsing()` reading a field other than `lukk.username`, the IP-independent login
  bucket is skipped (it was one bucket for everybody). Point `lukk.username` at your field to keep it.
- A `lukk-jwt` guard answers 401, not a PostgreSQL 500, for a `sub` its user column's type refuses
  (SQLSTATE 22P02 or 22003): `"admin"` against any integer column, or a number past a 32-bit
  `increments('id')`. A co-issuer minting non-numeric subjects hit this. For the stock auto-incrementing
  `id` a non-integer `sub` is refused without a query; for any other shape the refused lookup is read as
  no user. Inside a transaction of yours, an Eloquent provider's lookup runs in a savepoint so the refusal
  does not abort your transaction; a non-Eloquent provider's refusal there is rethrown, as before.
- `DELETE /auth/sessions/others` answers 409 for a token whose `fid` is empty, as for one without `fid`;
  `DELETE /auth/sessions` now also denylists the presenting token when it names no family of lukk's.

### `amr` now uses only RFC 8176 registered values

**High impact if anything reads `amr` — a gateway, a resource server, or your own `lukk.ability`-style
gates.**

| sign-in | before | now |
|---|---|---|
| password | `["pwd"]` | `["pwd"]` |
| password + TOTP or recovery code | `["pwd","otp"]` | `["pwd","otp","mfa"]` |
| passkey, user verified | `["webauthn"]` | `["pop","user","mfa"]` |
| passkey, presence only | `["webauthn"]` | `["pop","user"]` |
| passkey (presence only) + TOTP | `["webauthn","otp"]` | `["pop","user","otp"]` |

`webauthn` was never registered, so nothing outside lukk could interpret it. Replace a check for
`"webauthn"` with `"pop"`, and a check for "was this multi-factor" with `"mfa"`. Note the last row: a
presence-only passkey plus a TOTP is two POSSESSION factors, which NIST SP 800-63B-4 §2.2.1 does not
count as multi-factor, so it carries no `mfa`.

### `WebAuthnCeremony`: `verifyAssertion()` returns a `PasskeyAssertion`, and two new arguments

**Only if you implement `Lukk\Contracts\WebAuthnCeremony` yourself.** The shipped
`SpomkyWebAuthnCeremony` is already updated.

```php
public function authenticationOptions(string $challenge, array $allowCredentialIds, ?string $userVerification = null): array;

public function verifyAssertion(array $response, string $challenge, PasskeyRecord $stored, ?string $userVerification = null, int|string|null $owner = null): PasskeyAssertion;

public function isMultiFactor(PasskeyRecord $stored): bool;
```

- `$userVerification` is the requirement for THIS ceremony (`required`/`preferred`/`discouraged`), or
  null for your configured one. A step-up passes `required` when the account can reach AAL2, and you
  must enforce it on the assertion — not only put it in the options.
- `PasskeyAssertion::$multiFactor` must be true only when the assertion carries the UV flag AND the
  credential was already `uvInitialized` BEFORE this ceremony. Read it before verifying: a WebAuthn
  library typically updates it from the assertion as part of verification, and WebAuthn L3 §4 forbids
  relying on the flag in the ceremony that would set it. lukk skips an enrolled TOTP on this answer.
- `isMultiFactor()` reports whether a stored credential has shown user verification; false when unknown.
- `$owner` is the account a step-up expects the credential to belong to, or null at sign-in. Pass it
  to your library as the expected user handle (WebAuthn L3 §7.2 step 6): when the authenticator returns
  a `userHandle`, it must name that account.

### `FinishPasskeyLogin` no longer clears the password-confirm lockout itself

**Only if you call `Lukk\Actions\FinishPasskeyLogin` from your own code.** Call
`releaseConfirmLock($passkey)` once you have granted what the assertion was for — lukk does so after a
step-up passes the account-level check, and after a sign-in grants a session on a multi-factor
assertion. Releasing it for a presence-only key lets a stolen access token guess the password without
limit.

### A rebound `LockoutRepository` is called on every erasure and export

**Only if you implement `Lukk\Contracts\LockoutRepository` yourself.** `forget()` and
`summariesForSubjects()` now run whether or not a `lukk_lockouts` table exists; answer `0` and `[]`
for nothing stored.

### `PasskeyRepository::updateSignCount()` returns `bool`

**Only if you implement `Lukk\Contracts\PasskeyRepository` yourself.** Return whether the row was
written. The update must be forward-only — write only while the stored counter is below the new one —
so that of two concurrent assertions presenting the same counter, exactly one wins. lukk treats a
non-zero counter that did not advance as a cloned authenticator (WebAuthn L3 §6.1.1), refuses the
assertion and fires `PasskeyCloneDetected`; a repository that always answers `true` silently loses
that check, and one that always answers `false` refuses every non-zero counter.

A missing or mismatched method is a **fatal at class-load time**, not a catchable exception, so it
appears on the first request that resolves your binding rather than at boot.

### A rebound `PasskeyRepository` is called on every erasure, export and reset

**Only if you implement `Lukk\Contracts\PasskeyRepository` yourself.** `deleteForUser()` (account
deletion), `summariesForUser()` (account export) and, with `password_reset.revoke_passkeys` on,
`summariesForUser()` + `delete()` now run on every install, where they used to be skipped unless a
`passkeys` table existed. They must answer an empty store without throwing — `[]` and `0`.

### Under bcrypt, passwords over 72 bytes are refused — including at sign-in

bcrypt reads only the first 72 bytes, so lukk could verify a longer password only in part (NIST
SP 800-63B-4 §3.1.1.2 requires the whole of it). Registration, reset and change-password answer 422
for one; with `Lukk::registerValidation()` set or a rebound `RegisterRequest` overriding `rules()`, lukk adds that check (and "must be a string", and no NUL byte) after
your rules, since they replace its own (the 72-byte rule not when `Lukk::registerUsing()` does the create).
**Sign-in, step-up and change-password refuse one against a bcrypt hash** — and every earlier lukk
release stored such passwords, truncated, as does any import. Those users are typing the right
password; they get "This password is longer than 72 bytes, which can no longer be checked in full.
Reset your password to continue." and must reset. Consider telling them before you upgrade: you
cannot find them in the database (the hash does not record the length), but each refusal is a
`422` with that message. 36 two-byte characters already reach the
limit. Argon2 is unaffected.

### Passkey login can answer with a two-factor challenge

**Medium impact — if you use passkeys and two-factor together with your own client.** A passkey
assertion that is not multi-factor (no user verification, or a credential that never showed it) on an
account with confirmed two-factor now gets `{"two_factor": true, "challenge_token": "…"}` from
`POST /auth/passkeys/login`, exactly like a password sign-in, instead of a session. Complete it at
`POST /auth/two-factor-challenge`. lukk-js 0.12 handles this; an older client or your own must too.

### Passkey step-up: a new options route, and stricter rules

`POST /auth/confirm-passkey/options` (authenticated) negotiates a step-up ceremony: it asks the
authenticator for user verification when the account can reach AAL2 and lists the user's own
credentials. Use it instead of `passkeys/login-options` for a step-up (lukk-js does).

A presence-only passkey no longer earns a step-up on an account that has a password or a
user-verifying passkey: such an account can authenticate more strongly, and a step-up mints the token
that binds and removes authenticators (NIST SP 800-63B-4 §4.1.2.1). A password-less account whose
credentials are all presence-only can still step up with one — it has nothing stronger. That
refusal answers **422 on `credential`**, like a failed verification, not 403: on a step-up route 403
means the token itself may never confirm, and lukk-js abandons the prompt on it.

### A new `refresh_tokens.amr` column, and a new argument on `RefreshTokenRepository::persist()`

**Medium impact — every existing install adds a column; anyone implementing or subclassing
`RefreshTokenRepository` must update a signature.**

`amr` (RFC 8176 — how the session was authenticated: `["pwd"]`, `["pwd","otp","mfa"]`, `["pop","user"]`) was
stamped only at sign-in, so it disappeared from the first refreshed access token. A route gated on
it therefore stopped working roughly one `access_ttl` into every session: fail-closed if the gate was
written tightly, **fail-open** if it was written as `!isset($amr) || in_array(...)`. It is now stored
with the family and carried forward by every rotation.

1. Add the column. It went into the **existing** `create_refresh_tokens_table` migration, so how
   you get it depends on whether you have already run that migration:

   - **Fresh install / not yet migrated** — nothing to do. Publishing `lukk-migrations` and running
     `php artisan migrate` creates the column.
   - **You already ran it** (every existing install) — republishing does **not** help:
     `publishesMigrations` stamps the copy with a new timestamp, so `--force` produces a second
     `create_refresh_tokens_table` that fails with "table already exists". Add a migration of your own:

     ```php
     Schema::table('refresh_tokens', function (Blueprint $table) {
         $table->text('amr')->nullable();
     });
     ```

   Until you do, nothing breaks — the repository writes `amr` only when it has one and reads it as
   `null` when the attribute is absent, which is exactly the pre-upgrade behaviour.

2. If you implement `Lukk\Contracts\RefreshTokenRepository` yourself, or subclass
   `DatabaseRefreshTokenRepository` and override `persist()`, add the trailing argument:

   ```php
   public function persist(
       int|string $userId, string $familyId, ?string $previousId, string $tokenHash,
       int $expiresAt, ?string $scope = null, ?string $amr = null,
   ): void
   ```

   PHP raises a fatal on a mismatched signature, so this surfaces immediately rather than silently.
   Round-trip it like `scope`: store the string given and return it on `RefreshTokenRecord::$amr`. A
   repository that ignores it keeps the old behaviour — the claim is simply absent after the first
   refresh.

`amr` is now **reserved**, like `scope` and `pin`: it is applied after the `tokenClaimsUsing` merge,
so a claims hook can neither forge an authentication method the session never used nor erase the
real one.


### `POST /auth/logout` no longer requires a valid access token

**Medium impact — if a client relies on logout answering 401, uses cookie mode, or you rebound
`LogoutResponse`.**

Logout accepts a valid access token **or** the refresh token the client holds. What changes:

- A request with no usable credential answers **204** instead of 401, and revokes nothing. Logout is
  idempotent and never reveals whether a token existed.
- **Cookie mode:** the refresh cookie is used, and the clearing `Set-Cookie` sent, only when the
  request has `Content-Type: application/json` or `Sec-Fetch-Site: same-origin`/`none`. A client that
  POSTs to logout with no body from a sibling subdomain must now send `{}` as JSON (lukk-js does), or
  its cookie is neither revoked through logout nor cleared — the bearer still ends the session.
- A body `refresh_token` is read from a **JSON** body only, never a form body or the query string.
- The route has **no throttle**. Only refresh-token lookups that come up empty are counted
  (`rate_limits.refresh`, per guard and caller): a MISS, or a token whose family is **already
  revoked** — so a logout retried or replayed after the session ended costs the budget, while one that
  resolves to a live family costs nothing. Counted only when no valid bearer is presented; an
  exhausted bucket refuses the lookup up front. When it is throttled the answer is
  **429 with `Retry-After`** and the cookie is not cleared — the session is still live, so the client
  must retry rather than treat it as logged out.
- A consumed refresh token presented past the grace window dispatches `RefreshTokenReused` and
  revokes its family, exactly as `/refresh` does. An expired access token alone ends nothing.
- `LogoutResponse` now takes `bool $clearRefreshCookie = true`. A **rebound** implementation should
  honour it — sending the clearing cookie when it is false re-opens the forced-logout CSRF.

**Differences from running behind `auth:{guard}`**, for code that reads the request:

- With a valid bearer the request is still authenticated as its user (`$request->user()`,
  `Auth::user()`), and the active guard is set, before the session is revoked.
- With only a refresh token — or a valid bearer whose user no longer exists — nobody is authenticated
  and `$request->user()` is `null`, where the old route would have answered 401 and never reached
  your response.
- The `Authenticate` middleware no longer runs on this route, so anything attached through it (a
  middleware-priority hook, a guest redirect) does not apply.
- If you **extend** `AuthenticatedSessionController`: its constructor takes `EndSession` instead of
  `RevokeSession`, gained a trailing `ConfirmPasswordUnchanged $passwordUnchanged`, and `destroy()` no
  longer takes a `TokenVerifier`. `TwoFactorChallengedSessionController` likewise gained
  `ChallengeToken $challengeTokens` and `ConfirmPasswordUnchanged $passwordUnchanged`.

A test that used `/auth/logout` as a "does this token authenticate on this guard" probe should use an
`auth:{guard}` route instead.

### `DELETE /auth/sessions/others` no longer uses `LogoutResponse`

**Low impact — only if you rebound `LogoutResponse` and relied on it for this route.**

The route keeps the caller's session alive, but `LogoutResponse` ends the caller's session
client-side: in cookie mode it cleared the refresh cookie and the client could no longer refresh. It
now answers a bare `204` directly. A rebound `LogoutResponse` still applies to `POST /auth/logout` and
`DELETE /auth/sessions`.

One case changes for clients: a bearer token with no `fid` (a co-issuer's, in the verify-only
topology) now gets `409` instead of a `204` that revoked nothing, because there is no session to keep
and "log out my other devices" cannot be honoured. `Lukk::actingAs()` keeps the no-op.

### New: unclaimed sessions (`claim_seconds`) and `POST /auth/session/claim`

**Low impact — off by default; the route is new but inert until you set the key.**

```php
// config/lukk.php (top level, or per guard under `guards.{name}`)
'claim_seconds' => (int) env('LUKK_CLAIM_SECONDS', 0),   // e.g. 600
```

With a window set, the ORIGINAL credentials of a session started by a sign-in — its first access
token and never-rotated refresh token — are revoked (the whole family, `Events\SessionUnclaimed`) if the
session is not used within the window. **The contract:** every client must, within the window, call
`POST /auth/session/claim` (204, authenticated, not pin-gated), or make an authenticated request to this
lukk app, or refresh. A client that uses its access token only on another service must call the claim
route. The effective window is at least `access_ttl + leeway` and at least 60 seconds. Sessions with a
pinned grant are exempt.

The clamp only guarantees the original *access* token cannot be used past the window. A client that
does not make an authenticated request to this app or refresh within it — including one that uses the
token only on another service and refreshes after that service's 401 — must call the claim route.

If you implement `RefreshTokenRepository` yourself, populate `RefreshTokenRecord::$original` — whether the
row presented IS the family's own first, still-unrotated credential (for the shipped repository, exactly
`previous_id === null`). That is the signal the rule wants, and a repository reporting it owes nothing
else. Failing that, populate `RefreshTokenRecord::$createdAt` (the row's creation time), which lukk
compares against the marker within a couple of seconds; a `Lukk::useRefreshTokenModel` subclass then has
to keep `$timestamps` on. Report **neither** and no original is ever recognised, so nothing is revoked —
the feature is inert rather than dangerous — and lukk logs a warning once per worker process.

Markers live in the denylist cache store. Losing them fails open; restoring an old snapshot can at most
revoke a session still presenting its original sign-in refresh token after the window. A published
config without the key — or a cached one — leaves the feature off.

### An unverified two-factor user is refused at login

**Medium impact — only with `email_verification.block_unverified_login` on.**

The password step now answers **403** for an unverified account *before* issuing a challenge, and the
challenge route refuses one redeemed after the account became unverified. Previously an enrolled
account walked past the gate. `block_unverified_login` and `features.email_verification` are now also
read per guard.

### `features.logout_all` now does something

**Medium impact — only if your published config sets it to `false`.**

It was never read. `false` now removes `DELETE /auth/sessions` for that guard (a 404).

### Three `features` keys removed

**Low impact — no action.** `rotation`, `reuse_detection` and `denylist` were never honoured; those
behaviours are always on. A published config that still contains them keeps working — the keys are
simply ignored, as they always were. Delete them to avoid implying they are switches.

### `LockoutRepository` gained a method

**Medium impact — only if you implement `LockoutRepository` yourself.**

```php
+ public function summariesForSubjects(array $subjects, ?string $guard): array;
```

The read-side mirror of `forget()`, used by the account export: it must reach exactly the rows
`forget()` deletes, scoped to the guard. The export response gains a `lockouts` key.

### A sign-in no longer resets the account-wide login bucket, and non-account locks store a digest

**Low impact — no action for most apps.** A successful sign-in now clears only the caller's
per-address login bucket; the IP-independent `account_max_attempts` bucket decays instead of resetting.
A user who mistypes often may meet that cap after a success where before they would not. A persistent lock on an identifier that
names no account is now stored as `idn:sha256:<digest>` rather than the identifier in plain text.
Locks written before the upgrade keep their old key: `lukk:release`, account erasure and the export
still find them.

### Cookie mode: token routes require JSON

**Medium impact — only with `cookie_mode` on, and only for clients not sending JSON.** `login`,
`register`, `refresh`, `two-factor-challenge` and `passkeys/login` answer `415` unless the request has a
`Content-Type: application/json` body or comes from the same origin or the user's own navigation
(`Sec-Fetch-Site: same-origin` or `none`).
This closes login CSRF: a cross-site form could otherwise plant an attacker's session cookie. Send
JSON (`{}` for a cookie refresh), as lukk-js does.

### Request rules a client can hit

**Low impact — check custom clients.**

- `ceremony_id` on passkey login and step-up must be a UUID, which is what lukk issues; anything else
  is a `422` on `ceremony_id`.
- A refused passkey step-up is `422` on `credential`, not `403`.
- A password step-up is `422` on `password` on an account with an enforced second factor or a
  user-verifying passkey, unless the session's token carries `mfa` in `amr`. A token with no `amr` —
  after a refresh on a schema without the `amr` column, or from `startSession()` — counts as
  single-factor, so **migrate the `amr` column**, or users with a second factor must confirm with a
  passkey or sign in again after every refresh.
- Even in an `mfa` session, that allowance lasts only `confirm.mfa_max_age` (one day) after the sign-in,
  read from the new `auth_time` claim. Older sessions confirm with a passkey or sign in again.
  An `auth_time` more than `leeway` in the future, or not a timestamp at all, counts as no recent sign-in.
  `auth_time` is the sign-in time stored with the session (see above), so a session stored before
  this release needs a fresh multi-factor sign-in (or a passkey) to step up.
- `lukk.username` must be a plain column name (letters, digits, underscores) that does not contain
  `password`. Anything else throws an `InvalidArgumentException` naming the setting, on the first
  request that reads it. A dotted name that only worked because `Lukk::authenticateUsing` never
  touched a column must be renamed.

### `leeway` is capped at five minutes

`LUKK_LEEWAY` (and a per-guard `leeway`) is clamped to 0–300 seconds for every token lukk decodes —
access tokens, two-factor challenges, step-up confirmations, passkey challenges. RFC 7519 §4.1.4
allows "some small leeway"; a larger value kept an expired challenge usable for as long as it said.
A configured value above 300 now acts as 300; fix the clock skew instead.

### Per-guard overrides are honoured

`features.lockout`, the `lockout` block, `rate_limits.login.*` and `rate_limits.two_factor.*` are
read per guard. An extra guard that set
them in its `lukk.guards` block silently got the global values before; check that what it declares
is what you want enforced, since it now is.

### `password_reset.revoke_passkeys` (new, default off)

With it on, a reset removes every passkey and dispatches `PasskeyDeleted` for each. Keep
`revoke_sessions` on with it: a session that survives the reset can step up and enroll a new
passkey at once, so removing them achieves nothing.

### A custom password column is written

Reset and change-password now write the column `getAuthPasswordName()` names, as sign-in already
read it. Nothing to do unless you worked around the 500 by adding a `password` mutator; remove it.

### `lukk:secret --guard` validates the guard name

The name may contain only letters, digits, `_` and `-` (a dash becomes `_` in the variable). A
dotted name is refused rather than matched onto another guard's `LUKK_*_SECRET` line.

### New events when an authenticator is bound or removed

**Low impact — act on it.** NIST SP 800-63B-4 §4.1.2.1 requires telling the user, through another
channel, when an authenticator is bound. lukk sends no mail, so listen and notify:
`TwoFactorAuthenticationConfirmed`, `TwoFactorAuthenticationDisabled`, `RecoveryCodesGenerated`,
`PasskeyRegistered`, `PasskeyDeleted`, all in `Lukk\Events`.

### Sign-in, forgot-password and reset-password are padded to a wall-clock budget

**Low impact — check the budget.** A failed sign-in now takes at least `login_timebox_micros`
(500 ms), and every forgot-password request and every failed reset-password request at least
`password_reset.timebox_micros` (one second). A successful sign-in or reset returns early. Raise either budget if your slowest real path takes longer:
the box pads, it never shortens. Queue the reset notification if one second is too slow.

### A malformed `lukk.guards` is refused at boot

**Medium impact — only if your config has one.** A numeric guard name (under `lukk.guards`, or as
`lukk.guard`), a list of names (`['admin']` instead of `['admin' => [...]]`) or a truthy scalar now
throws at boot with a message naming the problem, where before it failed later with a `TypeError`
while the routes registered. `false` or `''` still mean "no extra guards".

### Two-factor challenges carry a password fingerprint, and are refused without one

**Medium impact — in the minutes around the deploy, and for co-issuers.** A challenge now carries
`pwf`, a fingerprint of the password it stands in for (an HMAC of the stored hash under `app.key`), and
is refused at redemption — before the code is checked, so nothing is spent — when that password has
changed or the challenge has no fingerprint. Consequences:

- A challenge minted by 0.6 and redeemed after the upgrade is refused; the user signs in again.
- A challenge minted by another service sharing the key (a co-issuer) carries no `pwf` and is refused.
- Deployments that redeem each other's challenges must share `APP_KEY` (and `app.previous_keys` across
  a key rotation), since the fingerprint is keyed with it.

### A per-guard `features.two_factor` that is null or `''` now challenges enrolled accounts

**Medium impact — if an extra guard sets the flag from an unset `env()`.** Only a value somebody set
(`false`, `0`, `'0'`) switches enforcement off. `null`, a blank `.env` line or a missing key used to
skip the second factor on that guard; enrolled accounts are now challenged, and the challenge route
mounts on the same rule. Set the flag explicitly if you meant "off".

### `AccountLocked` can fire twice for one run

**Low impact — if you notify on it.** A login failure counts against the identifier's fold and, when
the identifier resolves, against the account too; when both reach the cap, `AccountLocked` fires for
each. Only the account's (`id:` subject) names a user — the `idn:` one names no one, so a listener that
mails the owner should act on `id:` subjects and ignore the other.

### `AccountReleased` fires only for a held lock

**Low impact — if an audit log listens to it.** Clearing a counter that never reached the cap (every
successful sign-in after a typo did this) or a lock already past `release_after` no longer fires it.
A rebound `LockoutRepository` should follow the same rule: fire for a held lock only. `lukk:release` now
prints "No login lock was held for […]; cleared its failure count." (exit 0) when it cleared only a
counter or an already-expired lock; scripts matching "Released the … lock" see that line only for a
real release.

### A null `lukk.path` mounts the routes at `auth`

**Low impact.** An explicit `null` (an unset `env()`) used to mount the routes at the root. It now
means the default, `auth`. Set the path you want explicitly.

### `passkeys.challenge_ttl` defaults to 300 seconds (was 120)

**Low impact — no action unless you relied on two minutes.** The WebAuthn L3 §15.1 recommendation for
a user-verifying ceremony; options now also advertise it as `timeout`. An explicit
`LUKK_PASSKEY_CHALLENGE_TTL` is kept.

### Body mode: `/refresh` no longer reads the refresh cookie

**Low impact — no working client is affected.** Without `cookie_mode`, `POST /auth/refresh` reads only
the `refresh_token` field. A cookie left over from cookie mode (or planted by a sibling subdomain) is
ignored, so a body-mode client that somehow relied on it must send the field.

### Access-token time claims must be timestamps

**Low impact — co-issuers only.** `exp`, and `iat`/`nbf` when present, must be a number (or numeric
string) between the epoch and the end of year 9999; a fraction is fine. A co-issuer's token outside
that range now gets a `401`, where before it verified and later 500'd. A token whose `aud` is a JSON
object is refused too (RFC 7519 §4.1.3).

### Transactions and erasure run on the models' own connections

**Low impact — only with a model on another connection.** Rotation, bulk revocation and
recovery-code redemption open their transaction on the connection the model lives on (a
`useRefreshTokenModel` subclass, a user model on a directory connection), and erasure opens one on
each connection it writes to (the default, the password broker's and the token store's). Nothing to
do; noted because the transactions now appear on those connections.

### Password errors that were 500s are 422s

**Low impact — clients that special-cased a 500.**

- Confirm-password and change-password answer `422` on a stored hash the hasher refuses (another
  algorithm, a `$2b$` import with `hashing.bcrypt.verify` on), as sign-in already did.
- A recovery code stored under a hasher the app has since left is simply no match.
- Registration, reset and change-password refuse a new password that is not a string (`422`).
- Input that is not valid UTF-8 is refused with `422` before it reaches SQL: the sign-in identifier, a
  passkey `credential.id` (sign-in and step-up), a passkey name, and registration's `name` and non-email
  username. The sign-in password is not checked for it: one set as non-UTF-8 bytes keeps working.

### `auth_time` may be fractional; `confirm.mfa_max_age` may be a float

**Low impact.** A fractional `auth_time` (OIDC Core §2 allows it) counts as the second it falls in;
one before the epoch, or more than `leeway` in the future, counts as no recent sign-in.
`confirm.mfa_max_age` is compared as a float, so a "never" past the integer range works, and a
non-numeric value reads as 0 — the multi-factor allowance off — rather than comparing as a string.

### A `lukk.username` naming no column is refused in debug mode

**Low impact — a typo surfaces.** With `app.debug` on and the stock `EloquentUserProvider`, sign-in
checks that the `lukk.username` column exists and throws naming the setting if it does not. On
SQLite a typo used to read as a string literal that matched every row. Production skips the check.

### Changing the password needs a recent multi-factor session on a two-factor account

**Medium impact — if users change passwords from password-only sessions.** `POST /auth/password` on an
account with an enforced TOTP or a user-verifying passkey now requires the session to be a recent
multi-factor one (`amr` carries `mfa`, signed in within `confirm.mfa_max_age`), exactly as a password
step-up does. Otherwise it answers `422` on `current_password` before checking anything; the client
should have the user sign in again with their second factor or a user-verifying passkey (a step-up
confirmation does not satisfy this route).
Accounts with nothing stronger than the password are unaffected.

### Two-factor confirm and recovery-code regeneration answer `409` where they did nothing useful

**Low impact.** `POST /auth/two-factor/confirm` on an account whose two-factor is already confirmed,
and `POST /auth/two-factor/recovery-codes` on an account with no two-factor (confirmed or pending),
now answer `409` instead of succeeding. Neither changed anything a user needed.

### The account export: new passkey fields, and ISO-8601 throughout

**Medium impact — if you parse `GET /auth/account/export`.** Each `passkeys[]` entry is now
`credential_id`, `name`, `created_at`, `last_used_at`, `aaguid`, `transports`. `last_used_at` is an
ISO-8601 string (it was a unix integer), like every other timestamp in the export; `created_at` is
ISO-8601 too, and any of the time fields may be null. A rebound `PasskeyRepository` may return
`created_at` (unix int), `aaguid` and `transports` from `summariesForUser()`; a store that does not
exports null for them.

### Per-guard `two_factor.challenge_ttl`, `confirm.ttl` and `confirm.header`

**Low impact — if an extra guard overrides them.** They were read from the global block; an extra
guard's own values now apply. In particular a guard that sets its own `confirm.header` must have its
clients send the confirmation in that header.

### The refresh cookie's lifetime follows the session's

**Low impact — cookie mode.** The cookie's `Max-Age` is now what is left of the session's absolute
expiry, not a fresh `refresh_ttl` on every rotation. `TokenPair` gained an optional
`refreshExpiresAt`; code constructing one itself can leave it out (the cookie then gets the full
`refresh_ttl`, as before).

### A negative `leeway` counts as zero everywhere

**Low impact.** The verifier already clamped `leeway` to 0–300; the denylist TTLs and the
unclaimed-session window now use the same clamped value, so a negative or oversized setting behaves
the same on every side.

### Events serialize the user as an identifier

**Low impact — queued listeners.** `PasswordChanged`, `TwoFactorAuthenticationConfirmed`,
`TwoFactorAuthenticationDisabled`, `RecoveryCodesGenerated`, `PasskeyRegistered` and `PasskeyDeleted`
use `SerializesModels`: a queued listener receives the user re-read from the database when the job
runs. A user deleted before then makes the job fail with `ModelNotFoundException`, as for Laravel's
own `PasswordReset`; a listener that needs the user as it was must copy what it needs when queued.

### Logout clears the refresh cookie per guard

**Low impact — no action.** `LogoutResponse` reads `cookie_mode` through the guard's config, like
login and refresh already did.

---

## Upgrading to 0.6.0 from 0.5.x

### New routes: `DELETE /auth/account` and `GET /auth/account/export`

**High impact — `features.account_deletion` defaults to ON, so upgrading adds an irreversible route.**

If your application already has its own deletion flow, or deletion is owned by an identity provider,
or a retention obligation forbids it — turn it off:

```php
// config/lukk.php
'features' => ['account_deletion' => false],
```

Both routes require **step-up confirmation** *and* the `lukk.account.delete` ability. Step-up alone
is not enough to keep a machine token out: a pin carrying `lukk.account` can earn its *own*
confirmation. `lukk.account.delete` is deliberately not covered by `lukk.account`, and
`features.gate_auth_routes = false` does not switch this gate off — that flag exists to restore
pre-0.6 reach, and these routes have no pre-0.6 behaviour to restore. Erasure force-deletes the user
row by default — use
`Lukk::deleteUserUsing()` to anonymize instead, and remember the two-factor columns live *on* that
row, so a survivor keeps a working authenticator unless the callback clears them.

The export is the auth slice only. Serving it as a complete Art. 15 response would under-disclose;
append your own domain data.

### Two public signatures narrowed from `object` to `Authenticatable`

**Low impact — only if you call these with something that is not an authenticatable.**

```php
- Lukk\Support\VerifiedToken::forUser(Request $request, object $user)
+ Lukk\Support\VerifiedToken::forUser(Request $request, Authenticatable $user)
```

`Http\Resources\UserResource::abilities()` narrows the same way. These are RUNTIME types, so a
call with (say) a `stdClass` now raises a `TypeError` where it previously worked. `UserResource`
already required an authenticatable in practice — `toArray()` calls `getAuthIdentifier()`
unconditionally — so the narrowing states what was always true rather than removing a capability.

### The two-factor user provider is guard-scoped

**Low impact — no action; behaviour only differs on a guard that does not exist yet.**

`ChallengeTwoFactor` now resolves its user provider for the **active** guard rather than the default
one. Two-factor routes mount only on the default guard today, so nothing changes; but had an extra
guard gained them, a second factor would have been verified against the *default* provider's row
with the colliding id. `lukk:keygen --kid=0` also now emits the literal `0` instead of treating it
as absent (PHP falsiness), and console options are trimmed.

### A step-up confirmation is now bound to the session that earned it

**Low impact — informational, but a client that reuses a confirmation across tokens will see a new
423.** Nothing to configure.

A confirmation now carries the `fid` of the refresh-token family that re-verified the credential,
and `RequireConfirmation` refuses one from a different family with `423` and a machine-readable
`reason: confirmation_session_mismatch` (the plain "requires confirmation" 423 has no `reason`, so a
client can tell "earn one" from "discard this one and earn another"). `fid` is stable across
rotation, so refreshing mid-window keeps a confirmation valid and BFF mode is unaffected.

Bound to the subject alone, a confirmation was bearer authority across *every* token that subject
held — a machine token, which can never earn one itself because the earning routes are ability-gated,
could present the one the user's browser earned. The upgrade cost is one 423 and a re-confirm.

Matching is **strict**, which keeps the co-issuer topology working: a token minted by another service
sharing the secret legitimately carries no `fid`, and neither does a confirmation earned by it, so
`null === null` still passes. What is refused is an *unbound* confirmation presented by a bearer that
has one.

### Three contracts gained a method

**Medium impact — only if you implement `RefreshTokenRepository`, `PasskeyRepository` or
`LockoutRepository` yourself.** Callers need no change.

```php
// RefreshTokenRepository
+ public function deleteForUser(int|string $userId): int;
+ public function allForUser(int|string $userId): array;
// PasskeyRepository
+ public function deleteForUser(int|string $userId): int;
+ public function pruneOrphaned(): int;
+ public function existsByCredentialId(string $credentialId): bool;
// LockoutRepository
+ public function forget(array $subjects, ?string $guard): int;
```

These are **erasure, not revocation**. `revokeUserFamilies` stamps `revoked_at` and deliberately
keeps rows so a later replay still resolves to `reuse`; that is right for a logout and wrong for an
Art. 17 request.

`forget` takes a LIST because one account occupies three key spaces — `id:<user id>`,
`idn:<normalized identifier>` and the bare user id — and a guard, because two accounts sharing a
corporate email share a subject. Build the subjects with `LoginRateLimiter::lockoutSubject()`; the
raw identifier is never a key, so a sweep using it matches nothing.

Both `deleteForUser` implementations must be **guard-scoped**: an account is `(guard, id)`, and
providers are separate tables where colliding ids are the norm.

**Every `PasskeyRepository` method must now be guard-scoped except one**, not just `deleteForUser` —
including `findByCredentialId`, which is the assertion lookup and therefore an authentication
decision. The exception is `existsByCredentialId`, which must be **unscoped**: `credential_id` is
globally unique, so registration has to ask whether *any* guard holds an id before writing it, or a
cross-guard duplicate reaches the unique index as a 500 instead of a clean 422. lukk's
own implementation takes the guard as a constructor argument and is bound with **`bind`, not
`singleton`**: the active guard is per-request, so a memoized instance carries the previous request's
guard into the next one. If you bind your own implementation as a singleton, it will.

### A new nullable `guard` column on `passkeys`

**High impact if you run multiple guards *and* use passkeys — otherwise no action.**

`passkeys` had no `guard` column, so every read and write was a bare `where('user_id', ...)`. Under
multi-guard the providers are separate tables, where `users.id === admins.id` is the ordinary case
rather than a coincidence — so a credential could not be attributed to the account that owns it.
Three things followed, and the first is an authentication bypass:

- **`findByCredentialId` is the assertion lookup.** It takes a credential id and *no* user, so it is
  what decides who just authenticated. Unscoped, an admin's credential resolved on the users guard.
- **Erasure destroyed the colliding account's credentials.** `DELETE /auth/account` for a customer
  removed a live administrator's second factor.
- **Export disclosed them.** `GET /auth/account/export` handed the customer that administrator's
  device name and last-used timestamp — third-party behavioural data, which Art. 15(4) forbids.

`lukk:prune` compounded all three: it decided orphanhood against a single users table, so every
other provider's credential was orphaned *by construction*, and the command is scheduled **daily**.

The column lives in the **existing** `create_passkeys_table` migration, so how you get it depends on
whether you have already run it — same rules as the `scope` column below:

- **Fresh install / passkeys not yet migrated** — nothing to do.
- **You already ran `create_passkeys_table`** — republishing does not help (`vendor:publish` won't
  overwrite without `--force`, and `migrate` skips a filename already in the `migrations` table).
  Add the column, then **backfill it**:

  ```sql
  ALTER TABLE passkeys ADD COLUMN guard VARCHAR(255) NULL;
  ```

  ```sql
  -- Multi-guard only. Every existing row was written by ONE guard; name it, per guard.
  UPDATE passkeys SET guard = 'api';        -- then correct the rows that belong elsewhere
  ```

**Backfill or those rows go dark.** `NULL` means "the single-guard default" and is correct for a
single-guard install — lukk applies no scope and never touches the column, exactly as before. But
once `lukk.guards` is non-empty, lukk stamps every write with a guard name and scopes every read to
one, so a `NULL` row is invisible to *all* of them: it cannot be asserted, listed, erased, or
pruned. It is left alone rather than deleted, deliberately — a sweep must not destroy a credential
it cannot attribute — but it is also unusable until you name it.

> The same trap already applies to `refresh_tokens.guard` if you adopted `lukk.guards` after 0.4.0
> without backfilling. Both columns follow the identical rule: `NULL` is the single-guard default,
> and becomes invisible the moment a second guard exists.

**Going the other way — REMOVING a guard — needs the opposite cleanup, and it fails open.** The
scope is deliberately asymmetric: a `NULL` row is invisible under multi-guard (it fails closed, above),
but a *guard-stamped* row is fully visible once `lukk.guards` is empty again, because a single-guard
install applies no scope at all. For refresh tokens that means old families become revocable by the
default guard; for passkeys it is sharper, since `findByCredentialId` **is** the authentication
decision — the removed guard's authenticator would then log in as whichever account holds the same id
in the default provider. Before you drop a guard from `lukk.guards`, delete or re-home its rows:

```sql
DELETE FROM passkeys      WHERE guard = 'admin';
DELETE FROM refresh_tokens WHERE guard = 'admin';
```

**Storing a passkey now depends on the active guard.** `PasskeyRepository::store()` stamps whichever
guard is current, so a consumer registering a credential for a non-default guard outside lukk's own
routes must set it first — `Lukk::useGuard('admin')` — or the row lands on the wrong guard.

### Abilities (scopes)

**Low impact — entirely opt-in.** An install that never calls `Lukk::abilitiesUsing()` mints
byte-identical tokens and needs no action at all. Two things are worth reading if you do opt in.

### A new nullable `scope` column on `refresh_tokens`

**Medium impact — only if you want a session to own a *fixed* set of abilities.** Everyone else:
no action, including everyone using `abilitiesUsing`.

The column lives in the **existing** `create_refresh_tokens_table` migration, so how you get it
depends on whether you have already run that migration:

- **Fresh install / not yet migrated** — nothing to do. Publishing `lukk-migrations` and running
  `php artisan migrate` creates the column.
- **You already ran `create_refresh_tokens_table`** (every existing install) — republishing does
  **not** help. `vendor:publish` won't overwrite your copy without `--force`, and even with it
  `migrate` skips a filename already recorded in the `migrations` table. Add the column by hand:

  ```sql
  ALTER TABLE refresh_tokens ADD COLUMN scope TEXT NULL;
  ```

  or, if you have no refresh tokens worth keeping, roll back and re-run:

  ```bash
  php artisan migrate:rollback --step=1   # only if this is the last-run migration
  php artisan migrate
  ```

Skip it entirely if you don't pin grants — lukk reads the column defensively and the derived path
works unchanged without it.

```php
$table->text('scope')->nullable();
```

`NULL` — every existing row, and every row lukk writes unless you ask otherwise — means *derived*:
abilities come from `Lukk::abilitiesUsing()` on each mint, so revoking one takes effect within
`access_ttl`. A value means *pinned*: `StartSession` was given an explicit grant, and every rotation
of that family replays it verbatim. That is what a personal access token or a capped impersonation
session needs, and it is the only reason to add the column. lukk reads it defensively (`$row->scope
?? null`), so a pre-0.6 schema keeps working — you simply can't pin a grant until you migrate.

### The two swap-seam contracts changed shape

**Medium impact — only if you implement `TokenIssuer` or `RefreshTokenRepository` yourself.**
Callers need no change.

**`TokenIssuer::accessToken()` now takes a context object**, replacing the subject and family
arguments. Subject + family + guard was already three, and mint-time context keeps growing — a new
field goes into `TokenContext` without breaking every custom issuer again:

```php
- public function accessToken(int|string $userId, string $familyId, array $claims = []): array;
+ public function accessToken(TokenContext $context, array $claims = [], ?Abilities $abilities = null): array;
```

`$abilities` is the grant to stamp as `scope`, **already resolved by the calling Action**. Do not
derive it in your implementation: ability policy moved out of the issuer precisely so that rebinding
this contract can't silently drop `scope` — which, since the gates deny by default, would make every
ability-gated route answer 403 with nothing to explain it.

**`RefreshTokenRepository` gained `findByHash()` and an optional `$scope`:**

```php
+ public function findByHash(string $hash): ?RefreshTokenRecord;   // NON-locking read
  public function persist(…, int $expiresAt, ?string $scope = null): void;
```

`findByHash` is a plain read with no `FOR UPDATE`; `RotateRefreshToken` uses it to resolve the grant
*before* opening the transaction, so application code never runs while a row lock is held. A custom
repository that ignores `$scope` still works — it just can't pin a grant, so every session stays in
derived mode. If yours round-trips values through JSON or Redis, make sure `''` survives as `''`:
`null` means "derive per mint" and `''` means "pinned to nothing", and collapsing the two lets the
most restricted token you can issue widen to the subject's full grant on its first refresh.

### The `HasAbilities` trait is now `HasTokenAbilities`

**Low impact — a rename; one line per user model.**

It matches the contract it satisfies, the way Sanctum and the framework pair a trait and an interface
under one name:

```php
use Lukk\Concerns\HasTokenAbilities;
use Lukk\Contracts\HasTokenAbilities as HasTokenAbilitiesContract;

class User extends Authenticatable implements HasTokenAbilitiesContract
{
    use HasTokenAbilities;
}
```

### What a refresh-token row retains, now that it can hold entitlement

**Low impact — informational, but read it before you pin a grant.**

lukk cascades nothing when you delete a user: there is no foreign key on `refresh_tokens.user_id`
and no model observer. The token stops authenticating immediately (the guard can't resolve the
subject), but the **row** survives until `expires_at` — `refresh_ttl`, 30 days past its last
rotation by default — and only then if `lukk:prune` is actually running. Revoked-but-unexpired rows
are kept deliberately, so a replayed token still resolves to `reuse` rather than to `unknown`.

That was already true of `user_id`, `family_id` and the token hash. What changes in 0.6 is the
*kind* of data: a pinned grant means the row can also retain an entitlement record for a person you
have erased. Bounded and defensible as fraud detection, but it is your retention story to state.
Cascading deletes are on the roadmap; until then the published migration is yours to edit — adding
`->constrained()->cascadeOnDelete()` to `user_id` closes most of it.

### A second lukk guard now has to declare its own config block

**High impact — but only if you already have a `lukk-jwt` guard in `config/auth.php` with no
matching `lukk.guards` entry, in which case your install is currently unsafe.**

lukk now throws at boot for any `lukk-jwt` guard other than the default that has no
`lukk.guards.<name>` block. Previously such a guard inherited the default guard's `secret`,
`issuer` **and** `audience` — and audience is what stops one guard's token verifying on another, so
a token minted for your default guard would authenticate as a *different user* under the second
guard's provider. Give it its own block:

```php
'guards' => [
    'admin' => [
        'issuer' => 'https://admin.example.com',
        'audience' => ['https://admin.example.com'],   // MUST differ from every other guard
        'secret' => env('LUKK_ADMIN_SECRET'),          // ideally its own key too
        'path' => 'admin/auth',
    ],
],
```

### A pinned grant no longer manages other sessions

**Low impact — only if you issue pinned grants (`StartSession($id, $claims, [...])`).**

Two abilities are now required **from a pinned token** on lukk's own routes:

| Ability | Required by |
|---|---|
| `lukk.sessions` | `DELETE /auth/sessions`, `DELETE /auth/sessions/others` |
| `lukk.account` | `POST /auth/confirm-password`, `POST /auth/confirm-passkey`, `POST /auth/password` |

A token pinned to a narrow grant could previously log the account out everywhere, and step up — which
is the gateway to enrolling a passkey, disabling two-factor and regenerating recovery codes. Both
contradict what pinning a grant is for. Add whichever that token genuinely needs:

```php
$pat = $startSession($user->getKey(), [], ['ci.deploy', Abilities::SESSIONS]);
```

Ordinary sessions are unaffected — a derived grant carries no `pin` claim and is never gated — and
`logout` / `refresh` are never gated at all, so a pinned token can always end and renew itself. Set
`features.gate_auth_routes` to `false` to restore the old behaviour wholesale.

### `Lukk::actingAs()` in existing tests will 403 on a newly-gated route

**Low impact — test-suite only, and only once you add an ability gate.**

`actingAs($user, $guard)` records no token, and the gates read the token rather than the user — so a
gated route answers **403** (known, holds nothing) rather than letting the test through. Sanctum's
equivalent defaults to `['*']`; lukk's does not, because a default that grants everything is the
wrong default for an authorization feature. Pass the third argument:

```php
Lukk::actingAs($user, 'api', ['*']);            // abilities aren't what this test is about
Lukk::actingAs($user, 'api', ['orders.read']);  // ...or narrow, to test the gate itself
```

### `scope` is now a reserved claim

**Low impact — only if `tokenClaimsUsing` sets a claim literally named `scope`.**

Once `abilitiesUsing` is configured, the abilities layer owns `scope` and applies it *after* your
claims hook, so a `scope` from the hook is discarded. Without this a hook could grant itself
`admin.*`, and — worse — an empty grant failed to erase one, so `abilitiesUsing` returning `[]` for
a suspended user still minted the hook's value. If you were using `tokenClaimsUsing` to emit
`scope`, move it to `abilitiesUsing`; any other claim name is unaffected.

---

## Upgrading to 0.5.0 from 0.4.x

Most of 0.5.0 is opt-in (the account lockout) or invisible (the step-up throttle). Four things
change behaviour on an existing install; only the first two can be noticed by your users.

### New route: `POST /auth/password`

**Low impact — informational.**

`features.change_password` defaults to **on**, so upgrading adds one authenticated route. It needs
no configuration and no migration. If your app manages passwords elsewhere — an identity provider,
SSO, your own endpoint — set it to `false`.

Note it shares the step-up throttle (`rate_limits.confirm`) and, when `features.lockout` is on, the
`confirm` lockout counter. That's deliberate: it re-verifies the same secret, so a separate budget
would just widen the total allowance for guessing one password.

### The refresh cookie is now named per guard

**Medium impact — only if you use `cookie_mode` *and* [multiple guards](https://stsepelin.github.io/lukk-docs/multiple-guards).** Everyone else: no action.

Every guard used to set the same `__Host-refresh` cookie at `Path=/`. Guards may legitimately share
a host and differ only by path, so logging into one silently overwrote the other's cookie — each
login destroying the other session. Non-default guards now get a suffixed name
(`__Host-refresh-admin`); **the default guard's name is unchanged**, so a single-guard app is
untouched.

On deploy, sessions held in a non-default guard's cookie stop resolving and those users log in
again once. Nothing else is affected: the refresh-token rows are untouched, and a stale cookie is
rejected as `unknown` rather than crossing guards.

A per-guard `cookie_mode`, `refresh_ttl` and `cookie.*` are also honoured now — previously they
were read from the top level and a guard-level override was silently ignored. If you set one
expecting it to apply, it now does.

### `RefreshTokenReused` no longer fires for a post-logout retry

**Low impact — check your listener if you have one.**

The event carried `reason` of either `reuse` (a consumed token replayed after the grace window —
the theft signal) or `revoked` (a client retrying with a token it still held across a logout — an
ordinary, benign event). Both dispatched, and the docs tell you to treat the event as evidence of
theft, so a busy install produced a steady drip of false alarms over the one alarm that matters.

It now fires **only** for `reason === 'reuse'`. If you were filtering on `$event->reason` yourself,
that filter is now redundant but harmless. If you were counting *all* dispatches as a metric, the
number will drop — that drop is the false positives leaving.

The `revoked` path still force-revokes the family and still rejects the request; only the event
changed.

### Re-enrolling two-factor is refused instead of silently disabling it

**Low impact — only if your UI lets a user re-open the enrolment screen.**

`POST /auth/two-factor` on an account with **confirmed** 2FA used to overwrite the secret, null
`two_factor_confirmed_at` and regenerate the recovery codes. `hasEnabledTwoFactor()` then returned
false, so login stopped challenging: a user who reopened the QR screen out of curiosity and
wandered off was left unprotected, with nothing an app could hang a notification on.

It now returns **`409`** with a validation error on `two_factor`. To re-enrol, call
`DELETE /auth/two-factor` first — disabling should be a deliberate act, and that endpoint already
exists for it. If your UI has a "regenerate QR" button, point it at delete-then-enrol and tell the
user what it does.

### lukk refuses an `array` or `null` cache store in production

**Low impact — a misconfiguration you want to hear about.**

Token revocation, TOTP replay protection and passkey challenges all live in the cache
(`denylist_store`, falling back to your default store). An `array` store is per-process, so a
revoked token stays valid on every other worker and the single-use guarantees are not guarantees —
and it failed *silently*. Booting with one in `production` now throws with an actionable message.

Outside production nothing changes; the array driver stays the right default for a test suite, and
lukk's own suite runs on it.

### Custom `LockoutRepository` / `RefreshTokenRepository` implementations

**Medium impact — only if you rebound either contract.** The interfaces gained methods:

- `LockoutRepository::maxAttempts(): int` — the configured cap. Attempts are now *reserved*
  (incremented before the credential check) and compared against this, so concurrent requests can't
  each slip past a "not locked yet" read.
- `RefreshTokenRepository::countLiveTokens(string $familyId): int` — used only for the new
  `Events\RefreshFamilyForked` signal.
- `revokeUserFamilies()` / `revokeUserFamiliesExcept()` take an optional
  `?callable $before = null`, invoked with the family ids **inside** the transaction and before the
  rows are revoked. That is how the denylist write now happens in the safe order; an implementation
  that ignores it will revoke rows that were never denylisted.

## Upgrading to 0.4.0 from 0.3.x

### `refresh_tokens` gains a nullable `guard` column

**High impact — but only for installs that ran the migration before 0.4.0.**
**Fresh installs and anyone who hasn't published the migration yet: no action.**

Multi-guard scopes each refresh-token family to its guard via a new nullable `guard`
column on `refresh_tokens`. Because lukk is pre-1.0 with no stable installs, this column was
folded into the **existing** `create_refresh_tokens_table` migration rather than shipped as a
new one — so there is no additive migration to run.

- **Fresh install / not yet migrated** — nothing to do. Publishing `lukk-migrations` and
  running `php artisan migrate` creates the column.
- **You already ran the old `create_refresh_tokens_table`** (a pre-release install) — the new
  column won't exist. Add it once, by hand:

  ```sql
  ALTER TABLE refresh_tokens ADD COLUMN guard VARCHAR(255) NULL;
  ```

  or, if you have no refresh tokens worth keeping, roll the migration back and re-run it:

  ```bash
  php artisan migrate:rollback --step=1   # only if this is the last-run migration
  php artisan migrate
  ```

The column stays **null and unused under a single guard**, so existing token rows, refresh,
rotation, reuse detection, and logout-all are byte-for-byte unchanged. It only carries a value
once you configure `config('lukk.guards')`.

> Future (post-1.0) schema changes will ship as **additive migrations**, never as edits to a
> shipped migration.

### Multiple guards is opt-in — no action if you don't use it

Declaring a second guard requires `config('lukk.guards')` **and** a matching `lukk-jwt` guard
in `config/auth.php`. An app with an empty/absent `lukk.guards` behaves exactly as before. If
you **do** adopt it, note lukk now **refuses to boot** unless every guard has a distinct,
non-empty `audience` and mounts at a distinct path/domain, and every extra guard is declared
in `config/auth.php` — see the [Multiple Guards guide](https://stsepelin.github.io/lukk-docs/multiple-guards).

---

## Upgrading to 0.2.0 from 0.1.x

### Passkey `user_verification` defaults to `required`

**Medium impact — passkey installs only** (`features.passkeys` enabled). _Changed in 0.1.3._

The passkey ceremony now defaults `user_verification` to `required` (was `preferred`), so
passwordless login and passkey step-up enforce a biometric/PIN (phishing-resistant, AAL2).
Authenticators that can't verify the user will now be rejected at login/registration.

If you must support such authenticators, restore the old behavior:

```dotenv
LUKK_PASSKEY_UV=preferred
```

### Per-account login lockout

**Low impact.** Login now throttles per **account** (default 20 failed attempts/min, env
`LUKK_LOGIN_ACCOUNT_MAX_ATTEMPTS`) in addition to the existing per-email+IP limiter, to bound a
distributed brute force. Legitimate users are unaffected; a shared/automated account hammering
a wrong password can now hit the account cap. Tune or raise the env if that's your case.

### Passkey registration requests a resident (discoverable) credential

**Low impact — passkeys only.** Registration now requests `residentKey: required` so
usernameless/discoverable login works. Newly-registered passkeys are discoverable; existing
credentials are unaffected. No action needed.

---

## Upgrading to 0.1.3 from 0.1.2

### `/auth/*` errors are always JSON

**Low impact.** _Changed in 0.1.2._ lukk's `/auth/*` routes force `Accept: application/json`
so auth/validation failures render a clean `401`/`422` JSON regardless of the request's
`Accept` header or your app's exception config. If you somehow relied on these routes returning
an HTML/redirect error, that no longer happens. No action needed for API/SPA clients.

### Malformed auth input returns 422, not 500

**Low impact.** Auth request validation moved to FormRequests, so malformed input (e.g.
`code[]=x`) now returns a `422` instead of a `500`. This is a strict improvement; only relevant
if a test asserted the old `500`.
