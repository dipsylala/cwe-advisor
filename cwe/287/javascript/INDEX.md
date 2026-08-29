# CWE-287: Improper Authentication - JavaScript

## LLM Guidance

In Node.js applications, Improper Authentication commonly appears as a Passport.js `Strategy` verify callback that fetches a user record and calls `done(null, user)` without ever comparing a password hash, granting access to anyone who supplies a valid username. It also appears in JWT handling through the `jsonwebtoken` package: code that calls `jwt.decode()` - which performs no signature verification at all - and trusts the result, or code that calls `jwt.verify()` without pinning the `algorithms` option, leaving the token's own header free to select a weaker or mismatched algorithm. Fix by comparing a hashed credential in every verify callback and always calling `jwt.verify(token, key, { algorithms: [...] })` with an explicit allowlist.

## Key Principles

- In every Passport `Strategy` verify callback, compare the supplied credential against the stored hash with `bcrypt.compare()`/`argon2.verify()` before calling `done(null, user)`; call `done(null, false)` on any mismatch or missing user.
- Never call `done(null, user)` directly after a database lookup with no credential comparison - a callback that only checks "user exists" authenticates any known username.
- Compare against a dummy hash instead of returning early when the lookup misses - `bcrypt.compare(password, user?.passwordHash ?? DUMMY_HASH)` keeps both branches paying the same cost, where an early return answers an unknown username without ever reaching bcrypt.
- Make `DUMMY_HASH` a genuine bcrypt hash at the same cost as the stored ones. The `??` also covers a user row with no `passwordHash` (an SSO-only account): `bcrypt.compare` rejects a null or undefined hash through its callback or a rejected promise (`compareSync` throws), which answers that row with a `500` instead of a `401`.
- Passport regenerates the session itself from 0.6.0, which fixed CVE-2022-25896: `SessionManager.logIn` calls `req.session.regenerate()` and serializes the user inside that callback. Call `req.login()` on its own - wrapping it in a hand-rolled `req.session.regenerate()` regenerates twice, and Passport's own login example has no such wrapper. Pass `{ keepSessionInfo: true }` where pre-login state (a flash message, a CSRF token, a `returnTo` path) has to survive, since regeneration otherwise drops it, and note the session store must implement `regenerate` - `cookie-session` does not. On 0.5.x and earlier there is no internal regeneration and the manual wrapper is required.
- Always pass `{ algorithms: [...] }` explicitly to `jwt.verify()` rather than relying on `jsonwebtoken`'s key-format inference, so a token cannot switch algorithm families (e.g. RS256 to HS256) between issuance and verification.
- Never use `jwt.decode()` for authentication or authorization decisions - it only base64-decodes the payload and does not check the signature; reserve it for non-trust-boundary debugging.
- Store JWT and session secrets outside source control and rotate them if a forged or unsigned token is ever accepted in logs.
- Pin `jsonwebtoken` at 9.0.0 or later: through 8.5.1 it carries CVE-2022-23539/23540/23541, covering insecure default algorithm handling in `jwt.verify()` and weak key-type checking.
- Leave `ignoreExpiration` at its default (`false`) so `jwt.verify()` enforces `exp`/`nbf`; do not set it to `true` in production code paths.

## Taint Sinks

Passport `Strategy` `done(null, user)` without comparison, `jwt.decode()` for trust decisions, `jwt.verify()` without `algorithms`

## Remediation Steps

- Locate - Find `passport.use()` `Strategy` callbacks, and `jwt.verify()`/`jwt.decode()` call sites in authentication middleware
- Trace data flow - Follow the credential from the login request body into the verify callback, and the token from the `Authorization` header into `jwt.verify()`
- Replace the unsafe pattern - Add `bcrypt.compare()`/`argon2.verify()` to verify callbacks that skip password checks; replace any `jwt.decode()` used for a trust decision with `jwt.verify()`
- Bind, encode, validate, or authorize - Pass `{ algorithms: ['HS256'] }` (or the specific algorithm(s) actually used to sign) to `jwt.verify()`, matching only what the issuer produces
- Break taint after allowlist validation - Attach only the object returned by `jwt.verify()`/`done(null, user)` to `req.user`; do not merge in unverified decoded claims
- Harden configuration - Confirm `ignoreExpiration` is not set to `true`, and that Passport session serialization stores only a user id, not full claims
- Test - Time a right password, a wrong password, and an unknown username and assert all three are within noise of each other and all failures return `401`; capture the pre-login session cookie and confirm it no longer authenticates after login; write tests that submit a wrong password (expect rejection), a `jwt.decode()`-only bypass attempt, and a token re-signed with `alg: none` or a swapped algorithm (expect `jwt.verify()` to throw `JsonWebTokenError`)
