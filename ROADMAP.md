# Roadmap

No features are currently deferred — both items previously planned here have
shipped (see the [CHANGELOG](CHANGELOG.md)):

- **RS256 / ES256 + JWKS with key rotation** — asymmetric signing behind the
  `TokenIssuer`/`TokenVerifier` contracts, a `kid`-addressed key set, rotation
  with an overlap window, a `GET /auth/jwks` endpoint, and `lukk:keygen`.
- **Recovery-code count** — `GET /auth/two-factor/recovery-codes` reports how
  many codes remain (hashed storage kept; the codes themselves are never
  re-displayable).

Future ideas land here first, with a short design sketch, before implementation.
