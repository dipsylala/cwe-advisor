# CWE-347: Improper Verification of Cryptographic Signature - JavaScript

## LLM Guidance

The `jsonwebtoken` npm package added an opt-in `algorithms` restriction in 4.2.2 (fixing CVE-2015-9235), but only started auto-inferring `algorithms` from the verification key's type in **9.0.0** (GHSA-hjrf-2m68-5959) - on any 8.x or earlier release, a bare `jwt.verify(token, key)` with no `algorithms` option is still the classic vulnerable pattern, since nothing restricts the header's declared algorithm. From 9.0.0 on, a *static* key makes the omission safe, but a `getKey`/key-resolution callback whose returned key type varies with attacker-controlled input (the token's own `kid` or unverified header) shifts the auto-selected algorithm family with it and reopens algorithm confusion regardless of version. Always pass an explicit, hardcoded `algorithms` array as defense in depth. Never use `jwt.decode()` (which does not verify the signature) as a substitute for `jwt.verify()`. For non-JWT signatures such as webhook payloads, compare the computed HMAC with `crypto.timingSafeEqual()`, never `===` or `Buffer.equals()`.

## Key Principles

- Confirm `jsonwebtoken` is at least 9.0.0 (GHSA-hjrf-2m68-5959) - before it, omitting `algorithms` on `jwt.verify()` is the unmitigated classic bypass, not a hardened default; 4.2.2 (CVE-2015-9235) only made `algorithms` available to opt into, it did not add automatic inference
- Always pass an explicit, hardcoded `algorithms` array to `jwt.verify(token, key, { algorithms: [...] })` even on 9.0.0+, where the library infers one from the key's type - the inferred value tracks whatever key the resolver returned, so it offers no protection when the resolver is the attacker-influenced part
- Never use `jwt.decode()` in place of `jwt.verify()` - `decode()` returns the payload without checking the signature at all
- Never write a key-resolution function (a `getKey` callback passed to `verify()`, or one built on `jwt.decode(token, { complete: true })`) that chooses between an RSA public key and an HMAC secret based on the token's own unverified header or `kid`
- Keep RSA/EC public keys and HMAC secrets in separate variables and code paths; a public key must never be reachable as HMAC secret material
- For `kid`-based key lookup (a `getKey` callback backed by `jwks-rsa` or similar), resolve the key from a trusted key store and still pass the same `algorithms` restriction to `verify()`
- Use `crypto.timingSafeEqual()` for HMAC/signature comparisons, checking buffer lengths first since it throws on length mismatch instead of returning false

## Taint Sinks

`jwt.verify()` with a `getKey`/callback key resolver that branches on the token header or `kid`, `jwt.verify()` without `algorithms`, `jwt.decode()` used for authorization, `===`/`Buffer.equals()` on HMAC digests

## Remediation Steps

- Locate - find `jwt.verify(...)`, `jwt.decode(...)`, any custom HMAC comparison using `crypto.createHmac()`, and the installed `jsonwebtoken` version
- Trace data flow - confirm whether a key-resolution callback passed to `verify()` selects the key type or key material based on the token's own header, `kid`, or other attacker-supplied input
- Replace the unsafe pattern - upgrade `jsonwebtoken` to 9.0.0+ regardless of resolver pattern, since anything older has no key-type inference at all; add a hardcoded `algorithms` array to every `jwt.verify()` call on top of that; replace stray `jwt.decode()` authorization checks with `jwt.verify()`
- Bind, encode, validate, or authorize - if using `kid`-based key rotation, resolve keys only from a trusted JWKS/keystore and keep the algorithms restriction fixed
- Harden configuration - set `issuer`, `audience`, and `clockTolerance` options on `verify()`; reject tokens missing expected claims
- Test - re-sign a legitimate RS256 token as HS256 using the known public key as secret and confirm `verify()` throws `JsonWebTokenError`
