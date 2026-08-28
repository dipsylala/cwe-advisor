# CWE-347: Improper Verification of Cryptographic Signature - PHP

## LLM Guidance

`firebase/php-jwt` is vulnerable to algorithm confusion when the verification key is not bound to a specific algorithm, allowing an attacker to switch a token from RS256 to HS256 and sign it with the server's RSA public key treated as an HMAC secret. In `firebase/php-jwt` v6+, always pass a `Firebase\JWT\Key` object (or an array of `Key` objects keyed by `kid`) to `JWT::decode()` - each `Key` binds its key material to exactly one algorithm, so a token whose header claims a different algorithm is rejected. Do not use the deprecated pre-v6 calling convention that let the algorithm be less strictly bound to the key. For non-JWT signatures such as webhook payloads, compare the computed HMAC with `hash_equals()`, never `==` or `===`.

## Key Principles

- Always wrap the verification key in `new Key($keyMaterial, 'RS256')` (or the specific expected algorithm) before passing it to `JWT::decode()` - never pass a bare key string
- For `kid`-based key rotation, pass an associative array of `Key` objects (`['kid1' => new Key($key1, 'RS256'), ...]`) resolved from a trusted, server-side keystore - never build this array from unverified token contents
- Never disable or omit algorithm binding; upgrade off any pre-v6 `firebase/php-jwt` version that allowed weaker algorithm restriction on `JWT::decode()`
- Keep RSA/EC public keys and HMAC secrets in separate `Key` objects and code paths; a public key must never be reachable as HMAC secret material
- Reject the `none` algorithm and weak algorithms; only construct `Key` objects for the specific algorithm your issuer uses
- Use `hash_equals()` for HMAC/signature comparisons - never `==`, `===`, or `strcmp()`, none of which are constant-time

## Taint Sinks

`JWT::decode()` with a bare key string (no `Key` object), `hash_hmac()` compared with `==`/`===`/`strcmp()`

## Remediation Steps

- Locate - find `JWT::decode(...)` calls and any manual `hash_hmac(...)` comparisons
- Trace data flow - confirm every `JWT::decode()` call passes a `Key` object (not a bare string) and that the algorithm is not derived from the token itself
- Replace the unsafe pattern - wrap keys in `Firebase\JWT\Key` with an explicit algorithm; upgrade `firebase/php-jwt` to v6+ if still on an older major version
- Bind, encode, validate, or authorize - resolve `kid` lookups against a trusted keystore/JWKS array of `Key` objects, not attacker-supplied data
- Harden configuration - validate `iss`, `aud`, and `exp` claims after decoding, since `JWT::decode()` only verifies the signature and standard time-based claims
- Test - re-sign a legitimate RS256 token as HS256 using the known public key as secret and confirm `JWT::decode()` throws `UnexpectedValueException`
