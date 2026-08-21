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

## Upgrading to 0.5.0 from 0.4.x

Most of 0.5.0 is opt-in (the account lockout) or invisible (the step-up throttle). Four things
change behaviour on an existing install; only the first two can be noticed by your users.

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
