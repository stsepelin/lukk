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

## Upgrading to 0.6.0 from 0.5.x

Abilities are new and entirely opt-in — an install that never calls `Lukk::abilitiesUsing()` mints
byte-identical tokens and needs no action at all. Two things are worth reading if you do opt in.

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
