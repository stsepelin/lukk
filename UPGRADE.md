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
