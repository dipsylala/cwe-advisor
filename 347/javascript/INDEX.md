# CWE-347: Improper Verification of Cryptographic Signature - JavaScript

## LLM Guidance

The `jsonwebtoken` npm package is vulnerable to algorithm confusion when `jwt.verify()` is called without an explicit `algorithms` option, or when the verification key is chosen dynamically from `jwt.decode(token).header.alg` - an attacker can switch a token from RS256 to HS256 and sign it with the server's RSA public key used as the HMAC secret. Always call `jwt.verify(token, key, { algorithms: ['RS256'] })` with a fixed, hardcoded algorithms array, and never use `jwt.decode()` (which does not verify the signature) as a substitute for `jwt.verify()`. For non-JWT signatures such as webhook payloads, compare the computed HMAC with `crypto.timingSafeEqual()`, never `===` or `Buffer.equals()`.

## Key Principles

- Always pass an explicit, hardcoded `algorithms` array to `jwt.verify(token, key, { algorithms: [...] })` - never omit it and never derive it from the token itself
- Never use `jwt.decode()` in place of `jwt.verify()` - `decode()` returns the payload without checking the signature at all
- Never write a key-resolution function that inspects the unverified header (via `jwt.decode(token, { complete: true })`) to decide whether to use an RSA public key or an HMAC secret
- Keep RSA/EC public keys and HMAC secrets in separate variables and code paths; a public key must never be reachable as HMAC secret material
- For `kid`-based key lookup (a `getKey` callback backed by `jwks-rsa` or similar), resolve the key from a trusted key store and still pass the same `algorithms` restriction to `verify()`
- Use `crypto.timingSafeEqual()` for HMAC/signature comparisons, checking buffer lengths first since it throws on length mismatch instead of returning false

## Taint Sinks

`jwt.verify()` without `algorithms`, `jwt.decode()` used for authorization, `===`/`Buffer.equals()` on HMAC digests

## Remediation Steps

- Locate - find `jwt.verify(...)`, `jwt.decode(...)`, and any custom HMAC comparison using `crypto.createHmac()`
- Trace data flow - confirm whether the algorithm or key is ever chosen based on the token's own header or attacker-supplied input
- Replace the unsafe pattern - add a hardcoded `algorithms` array to every `jwt.verify()` call; replace stray `jwt.decode()` authorization checks with `jwt.verify()`
- Bind, encode, validate, or authorize - if using `kid`-based key rotation, resolve keys only from a trusted JWKS/keystore and keep the algorithms restriction fixed
- Harden configuration - set `issuer`, `audience`, and `clockTolerance` options on `verify()`; reject tokens missing expected claims
- Test - re-sign a legitimate RS256 token as HS256 using the known public key as secret and confirm `verify()` throws `JsonWebTokenError`

## Safe Pattern

```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// SAFE: algorithm is pinned - the token header cannot select HS256 instead
function verifyAccessToken(token, rsaPublicKey) {
  return jwt.verify(token, rsaPublicKey, {
    algorithms: ['RS256'],
    issuer: 'https://issuer.example.com',
    audience: 'my-api',
  });
}

// SAFE: webhook HMAC-SHA256 verification with constant-time comparison
function verifyWebhookSignature(requestBody, signatureHeader, webhookSecret) {
  const expected = crypto.createHmac('sha256', webhookSecret).update(requestBody).digest();
  const provided = Buffer.from(signatureHeader, 'hex');
  return expected.length === provided.length && crypto.timingSafeEqual(expected, provided);
}
```
