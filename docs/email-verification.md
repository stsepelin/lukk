# Email Verification

Lukk ships first-party email verification that fits the stateless-JWT model: a **signed link** the user clicks from their inbox, a **resend** endpoint, and a `lukk.verified` **gate** for routes that require a verified address. It's opt-in and rides Laravel's framework defaults — there's **no lukk migration**.

- [How it works](#how-it-works)
- [Setup](#setup)
- [Endpoints](#endpoints)
- [Sending the first email](#sending-the-first-email)
- [Gating routes](#gating-routes)
- [Blocking unverified login](#blocking-unverified-login)
- [Split-domain (SPA / BFF)](#split-domain)
- [Security notes](#security-notes)

<a name="how-it-works"></a>
## How it works

Verification state is Laravel's own `users.email_verified_at` column, and your user model implements `Illuminate\Contracts\Auth\MustVerifyEmail` — the same contract Laravel's `verified` middleware and `Verified` event already use. Lukk owns the **link** and the **gate**, not the storage:

1. Your app creates the user and triggers the verification email (Laravel's `Registered` event, or `$user->sendEmailVerificationNotification()`).
2. Lukk points that notification at a **signed, expiring** URL on its own route (`GET /auth/email/verify/{id}/{hash}`).
3. The user clicks it. Lukk validates the signature + the `{id}`/`{hash}` binding, marks the email verified, fires `Illuminate\Auth\Events\Verified`, and **redirects to your SPA** (or returns `204` to a JSON client).

The verify link is a **browser navigation, not an XHR** — that's why the signature is the authority (no session or bearer needed) and why the endpoint lives outside lukk's JSON-forcing group so it can redirect.

<a name="setup"></a>
## Setup

Your user model must implement `MustVerifyEmail` (Laravel's default `App\Models\User` already `use`s the trait — just add the interface), and your `users` table must have the framework-default `email_verified_at` column (it does, in a stock Laravel app). Then enable the feature:

```php
// app/Models/User.php
use Illuminate\Contracts\Auth\MustVerifyEmail;

class User extends Authenticatable implements MustVerifyEmail { /* ... */ }
```

```php
// config/lukk.php
'features' => [
    'email_verification' => true,
    // ...
],

'email_verification' => [
    'frontend_url' => env('LUKK_VERIFY_URL'), // e.g. https://app.example.com/verify-email
    'expire' => 60,                            // signed-link validity, minutes
    'block_unverified_login' => false,         // see "Blocking unverified login"
],
```

No migration to publish — `email_verified_at` is a Laravel default.

<a name="endpoints"></a>
## Endpoints

These routes are registered only when `features.email_verification` is enabled.

| Method | Path | Middleware | Purpose |
|---|---|---|---|
| `GET` | `/auth/email/verify/{id}/{hash}` | `signed` + throttle | The email-link target. Verifies, then redirects to `frontend_url` (browser) or returns `204` (JSON client). |
| `POST` | `/auth/email/verification-notification` | `auth` + throttle | Resend the verification link to the authenticated user (`202`). |

Both are throttled by the `lukk-email-verification` limiter (`rate_limits.email_verification`).

<a name="sending-the-first-email"></a>
## Sending the first email

Registration is your app's job (lukk is not a registration package). After creating the user, trigger the notification the way you already would:

```php
event(new \Illuminate\Auth\Events\Registered($user));
// or
$user->sendEmailVerificationNotification();
```

Because the feature is on, lukk has repointed Laravel's `VerifyEmail` notification at its signed route, so the link in the email lands on lukk's endpoint and bounces the user back to your `frontend_url`. Your app's mail template and styling are unchanged.

<a name="gating-routes"></a>
## Gating routes

Attach the `lukk.verified` middleware to any route that needs a verified email:

```php
Route::middleware(['auth:api', 'lukk.verified'])->group(function () {
    // ...routes that require a verified email
});
```

An unverified user gets a **409 Conflict** (distinct from a plain authz `403`, so your client can prompt "verify your email" specifically). The check reads the user's current `hasVerifiedEmail()` each request — never a token claim — so a user who just verified is unblocked without re-logging-in.

<a name="blocking-unverified-login"></a>
## Blocking unverified login

By default an unverified user **logs in normally** and you gate the sensitive routes (`lukk.verified`) — the SPA-friendly model (show a "verify your email" banner, allow resend). If you'd rather refuse login outright, set:

```php
'email_verification' => ['block_unverified_login' => true],
```

Now login returns **403** for an unverified `MustVerifyEmail` user and issues no tokens. The check runs only *after* a successful credential check, so it never affects the constant-time unknown-user / wrong-password path.

<a name="split-domain"></a>
## Split-domain (SPA / BFF)

The email link points at the **API** and redirects to your **SPA** (`frontend_url`), so it works in both direct and BFF deployments without a cross-origin round-trip:

- The user clicks the link → the browser navigates to the API → lukk verifies → redirects to `https://app.example.com/verify-email?verified=1`.
- Your SPA verify page then refreshes the session / reloads the user so the "unverified" UI clears.

On the client, the [lukk-js `useLukkEmailVerification` composable](https://stsepelin.github.io/lukk-js/) drives the resend + the post-redirect sync.

> [!NOTE]
> **Exposing the verified state to the client.** lukk-js reads `email_verified_at` (or a boolean `email_verified`) off your `user.endpoint` response to drive its `verified` state — so make sure your user resource **includes** that field. The optional `Lukk\Http\Resources\UserResource` emits a derived `email_verified` boolean for you (extend it to add your own fields); a bare Eloquent model already serializes `email_verified_at`. Keep the resource lean — it ships in the SSR HTML.

<a name="security-notes"></a>
## Security notes

- The link is a **signed, temporary URL** (HMAC over your `APP_KEY`, expiring per `expire`), bound to the user's current email via the `sha1(email)` hash — so a tampered link, an expired link, or a link for an email that has since changed all fail (`403`).
- Verification is **idempotent** — a double-clicked link marks once and fires `Verified` once.
- The gate is **fail-fresh**: `lukk.verified` reads `hasVerifiedEmail()` off the resolved user, not a JWT claim, so it can't be stale.
- No secret is ever placed in a token or logged.
