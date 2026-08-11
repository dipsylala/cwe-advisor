# CWE-347: Improper Verification of Cryptographic Signature - Python

## LLM Guidance

PyJWT requires an explicit `algorithms` list on every `jwt.decode()` call; omitting it raises an error, but passing a list that mixes algorithm families (for example `["RS256", "HS256"]`) while reusing the same key variable reopens algorithm confusion, since an attacker can switch a token to HS256 and sign it with the server's RSA public key treated as an HMAC secret. Always pin `algorithms` to the single expected algorithm and never derive it from the token's own header. For non-JWT signatures such as webhook payloads, compare the computed HMAC with `hmac.compare_digest()`, never `==`.

## Key Principles

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

## Safe Pattern

```python
import jwt
import hmac
import hashlib

# SAFE: algorithm is pinned - the token header cannot select HS256 instead
def verify_access_token(token: str, rsa_public_key) -> dict:
    return jwt.decode(
        token,
        rsa_public_key,
        algorithms=["RS256"],
        issuer="https://issuer.example.com",
        audience="my-api",
    )

# SAFE: webhook HMAC-SHA256 verification with constant-time comparison
def verify_webhook_signature(request_body: bytes, signature_header: str, webhook_secret: bytes) -> bool:
    expected = hmac.new(webhook_secret, request_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)
```
