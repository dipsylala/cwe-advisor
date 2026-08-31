# CWE-613: Insufficient Session Expiration - JavaScript

## LLM Guidance

`express-session`'s `cookie.maxAge` (milliseconds) governs the session cookie's lifetime, and if it's never set the cookie is non-persistent - gone when the browser closes, not expired on the server. `jsonwebtoken`'s `expiresIn` option has no default at all: omit it, and omit `exp` from the payload too, and the token this issues never expires. Both gaps show up together in real incidents - CVE-2025-3930 (Strapi) let a stolen or leaked JWT stay valid for its full default 30-day lifetime because logout and account deactivation never invalidated it. Set an explicit, deliberately short expiration on both, and build a revocation path for anything that must be invalidated sooner.

## Key Principles

- `express-session`'s `cookie.maxAge` has no default - an unset cookie is non-persistent (cleared at browser close) rather than server-enforced-expired, which is not the same guarantee. Set it explicitly, in milliseconds
- The `rolling` option (default `false`) resets the cookie's expiration to the original `maxAge` on every response when enabled - useful for idle timeout, but it also means a continuously-active session under `rolling: true` with a long `maxAge` has no independent absolute ceiling unless the application tracks session-start time separately
- `jsonwebtoken`'s `expiresIn` has no default value, and the library does not allow setting `exp` both in the payload and via `expiresIn` - omit both, and the issued token never expires
- `jwt.verify()` throws `TokenExpiredError` by default once `exp` has passed; suppressing this requires the caller to explicitly pass `ignoreExpiration: true`, so a codebase that does so has disabled a check that was already protecting it
- `jsonwebtoken` has no built-in revocation mechanism - closing the pre-expiry gap means a `jti`-keyed store of your own, or `jose`'s `SignJWT.setExpirationTime()` paired with the same external store, since neither library tracks issued tokens after signing
- CVE-2025-3930 (Strapi) is the concrete shape of this weakness: a JWT stayed valid for its full 30-day default after logout or account deactivation, and a token-renewal endpoint let a near-expiration token renew indefinitely - revocation and renewal both need to check the same invalidation state, not just the token's own signature

## Taint Sinks

`jwt.sign(payload, secret)` with no `expiresIn` option and no `exp` in the payload, `jwt.verify(token, secret, { ignoreExpiration: true })`, `express-session`/`cookie-session` configured with no `cookie.maxAge`, a token-renewal endpoint with no check against a revocation store

## Remediation Steps

- Locate - find `jwt.sign()` calls without `expiresIn`/`exp`, `express-session`/`cookie-session` configuration without `cookie.maxAge`, and any renewal or refresh endpoint
- Trace what the session or token authorizes, to size the lifetime to the risk
- Identify the unsafe pattern - a token or cookie with no expiration at all, an `ignoreExpiration: true` bypass, or a renewal endpoint that doesn't check revocation state
- Replace with an explicit, risk-sized `expiresIn`/`cookie.maxAge`
- Bind, encode, validate, or authorize - add a `jti`-keyed revocation store checked on both verification and renewal, or move to short-lived access plus refresh tokens
- Harden configuration - remove `ignoreExpiration: true` unless the caller is deliberately performing its own separate expiration check
- Test - confirm a token issued before the fix is rejected once its new, shorter expiration passes, and that a revoked token is rejected by both verification and any renewal path
