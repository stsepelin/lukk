# Passkeys

Lukk supports passkeys (WebAuthn / FIDO2) for **passwordless, phishing-resistant** login. A passkey is a public-key credential bound to your domain and stored on the user's device or password manager; logging in proves possession of the private key, which a phishing site can never obtain.

> [!NOTE]
> On the client, the [lukk-js passkey composables](https://stsepelin.github.io/lukk-js/passkeys) drive the browser `navigator.credentials` ceremony and the (de)serialization for the flows below.

- [Setup](#setup)
- [Endpoints](#endpoints)
- [Registering a Passkey](#registering-a-passkey)
- [Logging In With a Passkey](#logging-in-with-a-passkey)
- [Managing Passkeys](#managing-passkeys)
- [Split-Domain (BFF) Deployments](#split-domain-deployments)
- [Security Notes](#security-notes)

<a name="setup"></a>
## Setup

Install the WebAuthn library (the default ceremony adapter wraps it), publish and run the migration, enable the feature, and set your relying-party configuration:

```bash
composer require web-auth/webauthn-lib
php artisan vendor:publish --tag=lukk-passkey-migrations
php artisan migrate
```

```php
// config/lukk.php
'features' => [
    'passkeys' => true,
    // ...
],

'passkeys' => [
    'rp_id' => 'example.com',                  // registrable domain shared by app + api
    'origins' => ['https://app.example.com'],  // your front-end origin(s)
],
```

See [Configuration → Passkeys](configuration.md#passkeys) for every option.

> [!NOTE]
> The default adapter, `Passkeys\SpomkyWebAuthnCeremony`, works out of the box. To use a different WebAuthn library, rebind `Contracts\WebAuthnCeremony`.

<a name="endpoints"></a>
## Endpoints

These routes are registered only when `features.passkeys` is enabled.

| Method | Path | Middleware | Purpose |
|---|---|---|---|
| `POST` | `/auth/passkeys/registration-options` | `auth` + confirm | Get a registration challenge. |
| `POST` | `/auth/passkeys` | `auth` + confirm | Verify the attestation and store the credential. |
| `POST` | `/auth/passkeys/login-options` | `throttle` | Get an assertion challenge → `{ ceremony_id, options }`. |
| `POST` | `/auth/passkeys/login` | `throttle` | Verify the assertion → token pair (`amr: ["webauthn"]`). |
| `POST` | `/auth/confirm-passkey` | `auth` | Satisfy [step-up confirmation](confirmation.md) with a passkey. |
| `GET` | `/auth/passkeys` | `auth` | List the user's credentials. |
| `DELETE` | `/auth/passkeys/{id}` | `auth` + confirm | Revoke a credential. |

<a name="registering-a-passkey"></a>
## Registering a Passkey

Registration happens while the user is logged in (and has [confirmed](confirmation.md) their identity):

1. The client requests options from `/auth/passkeys/registration-options` and passes them to the browser's `navigator.credentials.create()`.
2. The browser returns an attestation, which the client posts to `/auth/passkeys`. Lukk verifies it and stores the credential.

```mermaid
sequenceDiagram
    participant App as App (client)
    participant B as Browser + Authenticator
    participant API as lukk API

    App->>API: POST /auth/passkeys/registration-options (auth + confirm)
    API-->>App: { challenge, rp, user, ... }  (challenge cached per user)
    App->>B: navigator.credentials.create(options)
    B-->>App: attestation (new credential + public key)
    App->>API: POST /auth/passkeys { credential }
    Note over API: verify attestation vs cached challenge,<br/>rp_id + origin; store credential (COSE key encrypted)
    API-->>App: 204 No Content
```

<a name="logging-in-with-a-passkey"></a>
## Logging In With a Passkey

Login is fully passwordless:

1. The client requests options from `/auth/passkeys/login-options`. The response includes an opaque `ceremony_id` and the WebAuthn `options`; pass the options to `navigator.credentials.get()`.
2. The browser returns an assertion, which the client posts to `/auth/passkeys/login` along with the `ceremony_id`. Lukk verifies the signature and returns the normal [token pair](authentication.md#logging-in), carrying `amr: ["webauthn"]`.

```mermaid
sequenceDiagram
    participant App as App (client)
    participant B as Browser + Authenticator
    participant API as lukk API

    App->>API: POST /auth/passkeys/login-options
    API-->>App: { ceremony_id, options.challenge }  (challenge cached by ceremony_id)
    App->>B: navigator.credentials.get(options)
    B-->>App: assertion (signed by the private key)
    App->>API: POST /auth/passkeys/login { ceremony_id, credential }
    Note over API: pull+verify challenge (single-use), origin/rp_id,<br/>signature vs stored public key, sign-count; resolve user
    API-->>App: 200 { access_token, refresh_token } · amr ["webauthn"]
```

The challenge is server-generated, single-use, and held server-side (in the cache) — it never travels inside a JWT.

<a name="managing-passkeys"></a>
## Managing Passkeys

`GET /auth/passkeys` lists the current user's credentials, and `DELETE /auth/passkeys/{id}` revokes one (behind step-up confirmation).

<a name="split-domain-deployments"></a>
## Split-Domain (BFF) Deployments

When your front-end and API live on different subdomains (`app.example.com` and `api.example.com`), set:

- **`rp_id`** to the registrable domain they share — `example.com`, **not** `api.example.com`.
- **`origins`** to include the front-end origin — `https://app.example.com` — because the browser reports the front-end's origin, not the API's.

<a name="security-notes"></a>
## Security Notes

- Credential IDs are globally unique, and the COSE public key is **encrypted at rest**.
- A regressing signature counter is rejected and dispatches `Events\PasskeyCloneDetected`, but a `0` counter is never flagged — synced passkeys (iCloud, Google, 1Password) always report `0`.
- `rp_id` and `origins` are **required** when passkeys are enabled — lukk throws on an empty value rather than fall back to a weak default.
- By default lukk requests **user presence** (a tap). For phishing-resistant, AAL2-style login and step-up — requiring biometric/PIN — set `user_verification` to `required` (see [Configuration](configuration.md#passkeys)). It applies to both passwordless login and `confirm-passkey` step-up.
- Passkey storage sits behind `Contracts\PasskeyRepository` (`passkeys` table) and is swappable.

> [!WARNING]
> Passkeys are only as phishing-resistant as your weakest fallback. In Lukk's default model, password login is always available — so deleting all passkeys can never lock a user out. For a **passwordless-only** deployment, guard the last credential at your application layer and ensure any recovery path is itself phishing-resistant; otherwise an attacker can downgrade to the weaker method.
