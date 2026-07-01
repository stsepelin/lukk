---
layout: home

hero:
  name: Lukk
  text: First-party JWT auth for Laravel
  tagline: Short-lived access tokens, rotating refresh tokens with reuse detection, and instant revocation — plus optional two-factor and passkeys. Not Passport, not OAuth ceremony.
  actions:
    - theme: brand
      text: Get Started
      link: /introduction
    - theme: alt
      text: Configuration
      link: /configuration
    - theme: alt
      text: GitHub
      link: https://github.com/stsepelin/lukk

features:
  - title: Modern token model
    details: Short-lived HS256 access JWTs + opaque rotating refresh tokens with reuse detection, a concurrency grace window, and a cache-backed denylist for instant revocation.
  - title: Minimal dependencies
    details: One runtime dependency (firebase/php-jwt). No hand-rolled JWS. Optional, feature-gated 2FA (TOTP) and passkeys (WebAuthn) are the only sanctioned extras.
  - title: Sanctum-style customization
    details: Every moving part is a contract bound to a default (rebind it) or a closure hook on the static Lukk class — custom login logic, storage, models, responses, and claims. You never edit the package.
  - title: First-party by design
    details: No authorization-code / PKCE ceremony. Login, refresh, logout, session revocation, and step-up confirmation, with RS256/ES256 + JWKS available behind the contracts.
---
