# CWE-347: Improper Verification of Cryptographic Signature - Python

## LLM Guidance

PyJWT (2.0.0+) requires an explicit `algorithms` list on every `jwt.decode()` call and raises if it's omitted, and its `HMACAlgorithm.prepare_key()` blocklists PEM- and SSH-formatted key material from being used as an HMAC secret specifically to stop algorithm confusion. That blocklist has had at least one documented gap: CVE-2022-29217 (GHSA-ffqj-6fqr-9h24), fixed in **2.4.0**, where SSH-formatted Ed25519 public keys weren't recognized, letting an attacker sign a token HS256 using the server's Ed25519 public key as the HMAC secret. Require PyJWT 2.4.0+, always pin `algorithms` to the single expected algorithm, and never derive it from the token's own header. For non-JWT signatures such as webhook payloads, compare the computed HMAC with `hmac.compare_digest()`, never `==`.

## Key Principles

- Confirm PyJWT is at least 2.4.0 (CVE-2022-29217) - the key-format blocklist that stops an asymmetric key from being reused as an HMAC secret has had gaps for specific key formats, so the version matters as much as the calling convention
- Always pass `algorithms=["RS256"]` (or the specific expected algorithm) to `jwt.decode()` - never pass `None`, an empty list, or a list mixing symmetric and asymmetric algorithms for the same key
- Never call `jwt.decode(token, options={"verify_signature": False})` or use `jwt.get_unverified_header()`/`jwt.get_unverified_claims()` results to make authorization decisions
- Never choose the verification key based on `jwt.get_unverified_header(token)["alg"]` - resolve keys by `kid` from a trusted, server-side keystore or JWKS, keeping the algorithm expectation fixed
- Keep RSA/EC public keys and HMAC secrets as separate objects; load asymmetric keys with `cryptography`'s key-loading functions so they cannot be reused as raw HMAC byte material
- Validate `iss`, `aud`, and `exp` via `jwt.decode()`'s built-in `issuer=`/`audience=`/`options={"require": [...]}` arguments rather than checking claims manually after decoding
- Use `hmac.compare_digest()` for any HMAC or signature comparison - never `==`, which short-circuits and leaks timing information

## Taint Sinks

`jwt.decode()` without `algorithms`, `options={"verify_signature": False}`, `hmac.new()` result compared with `==`

## Remediation Steps

- Locate - find `jwt.decode(...)`, `jwt.get_unverified_header(...)`, and any manual `hmac.new(...)` comparisons
- Trace data flow - check whether the algorithm or key is ever selected using unverified token contents
- Replace the unsafe pattern - add an explicit `algorithms=[...]` argument to every `decode()` call; remove any `verify_signature: False` debug code from production paths
- Bind, encode, validate, or authorize - resolve signing keys by `kid` from a trusted keystore/JWKS and pass the matching single algorithm to `decode()`
- Harden configuration - set `options={"require": ["exp", "iss", "aud"]}` and pass `issuer=`/`audience=` to `decode()`
- Test - re-sign a legitimate RS256 token as HS256 using the known public key as secret and confirm `decode()` raises `InvalidAlgorithmError`
