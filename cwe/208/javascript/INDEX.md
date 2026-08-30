# CWE-208: Observable Timing Discrepancy - JavaScript

## LLM Guidance

In Node.js, timing discrepancies typically appear when secrets (password hashes, HMAC digests, API tokens) are compared with `===` or `Buffer.equals()`, neither of which is guaranteed constant-time. Use `crypto.timingSafeEqual(a, b)` for any comparison involving a secret - it compares two `Buffer`/`TypedArray` values in constant time. It requires both inputs to be the same byte length and throws a `RangeError` otherwise, so check lengths separately or normalize both values to a fixed length (e.g. by hashing) before comparing. This is Node.js-specific; browser-side JavaScript has no equivalent and should not be comparing server secrets client-side.

## Key Principles

- Use `crypto.timingSafeEqual(a, b)` for any comparison involving a secret, never `===`, `==`, or `Buffer.equals()`
- Both arguments must be `Buffer`/`TypedArray` of the same byte length, or `timingSafeEqual()` throws - guard the length check separately, or normalize both values to a fixed length before comparing so the length check itself doesn't leak information
- Do not write a custom constant-time comparison loop in JavaScript - engine-level optimizations can reintroduce timing variance a hand-written loop is meant to avoid; use the `crypto` module's implementation instead
- Apply this to every secret comparison: password hashes, HMAC signatures, API keys, session tokens, CSRF tokens
- Libraries like `jsonwebtoken` already handle signature comparison internally - the risk is in manual HMAC/signature verification, hand-rolled token checks, and the login control flow around them
- The comparison operator is rarely the biggest leak in an Express/Passport login: a `LocalStrategy` verify callback that returns `done(null, false)` on an unknown username *before* calling `bcrypt.compare()` skips the hash entirely, producing a timing gap orders of magnitude larger than any `===` on a token. Compare against a real dummy hash of the same algorithm and cost on every unknown-user path - `bcrypt.compare(password, '')` does not work as that dummy, since an empty string has no parseable cost factor and returns near-instantly, reopening the same gap
- `Buffer.from(str, 'hex')` does not throw on malformed hex - it silently stops at the first invalid byte pair and returns whatever it decoded so far, shorter than expected. A length check downstream is then implicitly catching that truncation, not just enforcing a length rule; validate the input is well-formed hex before decoding rather than relying on the length side effect

## Taint Sinks

`===`/`==` used to compare a secret value (password hash, HMAC digest, API key, session token), `Buffer.equals()`

## Remediation Steps

- Locate - find comparisons of secret values (password hashes, tokens, HMAC digests) using `===`, `==`, or `Buffer.equals()`
- Trace data flow - confirm the value comes from a security-sensitive source (stored credential, computed HMAC, session store)
- Replace with the safe pattern - convert both values to same-length `Buffer`s and use `crypto.timingSafeEqual(a, b)`
- Handle length mismatches safely - hash both values to a fixed length first, or compare lengths only as a non-secret-dependent precondition
- Test - verify the comparison still returns the correct boolean for matching and non-matching inputs
