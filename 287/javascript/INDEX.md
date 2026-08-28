# CWE-287: Improper Authentication - JavaScript

## LLM Guidance

In Node.js applications, Improper Authentication commonly appears as a Passport.js `Strategy` verify callback that fetches a user record and calls `done(null, user)` without ever comparing a password hash, granting access to anyone who supplies a valid username. It also appears in JWT handling through the `jsonwebtoken` package: code that calls `jwt.decode()` - which performs no signature verification at all - and trusts the result, or code that calls `jwt.verify()` without pinning the `algorithms` option, leaving the token's own header free to select a weaker or mismatched algorithm. Fix by comparing a hashed credential in every verify callback and always calling `jwt.verify(token, key, { algorithms: [...] })` with an explicit allowlist.

## Key Principles

- In every Passport `Strategy` verify callback, compare the supplied credential against the stored hash with `bcrypt.compare()`/`argon2.verify()` before calling `done(null, user)`; call `done(null, false)` on any mismatch or missing user.
- Never call `done(null, user)` directly after a database lookup with no credential comparison - a callback that only checks "user exists" authenticates any known username.
- Compare against a dummy hash instead of returning early when the lookup misses - `bcrypt.compare(password, user?.passwordHash ?? DUMMY_HASH)` keeps both branches paying the same cost, where an early return answers an unknown username in 0.004 ms against 231 ms for a wrong password.
- Make `DUMMY_HASH` a genuine bcrypt hash at the same cost as the stored ones; `bcrypt.compare(password, '')` returns in 0.028 ms and closes nothing. The `??` also covers a user row with no `passwordHash` (an SSO-only account), which would otherwise throw and answer that row with a `500`.
- In an Express login route, call `req.session.regenerate()` and issue `req.login()` from inside its callback: regenerating after `req.login()` throws away the session Passport just populated, and skipping it lets a session ID an attacker planted before login become the authenticated one.
- Always pass `{ algorithms: [...] }` explicitly to `jwt.verify()` rather than relying on `jsonwebtoken`'s key-format inference, so a token cannot switch algorithm families (e.g. RS256 to HS256) between issuance and verification.
- Never use `jwt.decode()` for authentication or authorization decisions - it only base64-decodes the payload and does not check the signature; reserve it for non-trust-boundary debugging.
- Store JWT and session secrets outside source control and rotate them if a forged or unsigned token is ever accepted in logs.
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
