# CWE-287: Improper Authentication - JavaScript

## LLM Guidance

In Node.js applications, Improper Authentication commonly appears as a Passport.js `Strategy` verify callback that fetches a user record and calls `done(null, user)` without ever comparing a password hash, granting access to anyone who supplies a valid username. It also appears in JWT handling through the `jsonwebtoken` package: code that calls `jwt.decode()` - which performs no signature verification at all - and trusts the result, or code that calls `jwt.verify()` without pinning the `algorithms` option, leaving the token's own header free to select a weaker or mismatched algorithm. Fix by comparing a hashed credential in every verify callback and always calling `jwt.verify(token, key, { algorithms: [...] })` with an explicit allowlist.

## Key Principles

- In every Passport `Strategy` verify callback, compare the supplied credential against the stored hash with `bcrypt.compare()`/`argon2.verify()` before calling `done(null, user)`; call `done(null, false)` on any mismatch or missing user.
- Never call `done(null, user)` directly after a database lookup with no credential comparison - a callback that only checks "user exists" authenticates any known username.
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
- Test - Write tests that submit a wrong password (expect rejection), a `jwt.decode()`-only bypass attempt, and a token re-signed with `alg: none` or a swapped algorithm (expect `jwt.verify()` to throw `JsonWebTokenError`)

## Safe Pattern

```javascript
// SAFE: Passport local strategy compares a password hash, not just user existence
const bcrypt = require('bcrypt');
const { Strategy: LocalStrategy } = require('passport-local');

passport.use(new LocalStrategy(async (username, password, done) => {
  const user = await User.findOne({ username });
  if (!user) return done(null, false, { message: 'Invalid credentials' });

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return done(null, false, { message: 'Invalid credentials' });

  return done(null, user);
}));

// SAFE: jsonwebtoken verify with a pinned algorithm - never jwt.decode() for trust decisions
const jwt = require('jsonwebtoken');

function verifyToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
}
```
