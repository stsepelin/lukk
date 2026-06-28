# Lukk Documentation

Minimal-dependency JWT authentication for **first-party** Laravel applications — short-lived access tokens, rotating refresh tokens with reuse detection, and instant revocation, with optional two-factor authentication and passkeys.

> **Unofficial, independent package.** Not affiliated with or endorsed by the Laravel team. "Laravel" and "Sanctum" are referenced only to describe design influence and compatibility.

## Getting Started

- [Introduction](introduction.md) — what Lukk is, the token model, and when to use it
- [Installation](installation.md) — install, generate the secret, wire the guard
- [Configuration](configuration.md) — every option, explained

## Core

- [Authentication](authentication.md) — the login, refresh, and logout endpoints, protecting routes, and output modes
- [Customization](customization.md) — swap any moving part: login logic, storage, models, responses, claims
- [Events & Maintenance](events.md) — security events, token pruning, and testing

## Additional Features

- [Two-Factor Authentication](two-factor-authentication.md) — TOTP with recovery codes
- [Passkeys](passkeys.md) — passwordless, phishing-resistant WebAuthn login
- [Confirmation](confirmation.md) — step-up ("sudo") confirmation for sensitive routes

## Reference

- [Deployment](deployment.md) — single service, splitting auth from the API, multiple audiences, independent verifiers
- [Architecture & Security](architecture.md) — design rationale, standards mapping, and the security checklist
