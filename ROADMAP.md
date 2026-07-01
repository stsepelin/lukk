# Roadmap

Future ideas land here first, with a short design sketch, before implementation.

_No features are currently deferred._

## Shipped

Previously planned here, now shipped (see the [CHANGELOG](CHANGELOG.md)):

- **Email verification** — opt-in `features.email_verification`. A signed-link verify
  endpoint (`GET /auth/email/verify/{id}/{hash}`, outside the JSON-forcing group,
  content-negotiating a redirect to your SPA or a `204`), a resend endpoint, the
  `lukk.verified` **409** gate (read fresh off the user, never a token claim), and an
  optional `block_unverified_login` **403**. Stateless — rides Laravel's
  `email_verified_at` / `MustVerifyEmail`, no migration. The optional access-token
  `email_verified` **claim was deferred**: the DB-backed gate is always-fresh, and a
  mutable claim adds refresh-path complexity for the verify-only-API niche only —
  revisit on demand.
- **RS256 / ES256 + JWKS with key rotation** — asymmetric signing behind the
  `TokenIssuer`/`TokenVerifier` contracts, a `kid`-addressed key set, rotation
  with an overlap window, a `GET /auth/jwks` endpoint, and `lukk:keygen`.
- **Recovery-code count** — `GET /auth/two-factor/recovery-codes` reports how
  many codes remain (hashed storage kept; the codes themselves are never
  re-displayable).
