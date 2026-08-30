# CWE-347: Improper Verification of Cryptographic Signature - PHP

## LLM Guidance

`firebase/php-jwt` is vulnerable to algorithm confusion when the verification key is not bound to a specific algorithm, allowing an attacker to switch a token from RS256 to HS256 and sign it with the server's RSA public key treated as an HMAC secret - this is CVE-2021-46743 (GHSA-8xf4-w7qw-pjjw), exploitable via the `kid` header when a key ring mixes key types, fixed in **6.0.0**. On 6.0.0+, always pass a `Firebase\JWT\Key` object (or an array of `Key` objects keyed by `kid`) to `JWT::decode()` - each `Key` binds its key material to exactly one algorithm, so a token whose header claims a different algorithm is rejected. Pre-6.0.0, `decode()` took the allowed algorithms as a separate array parameter rather than bound to the key, which is what CVE-2021-46743 exploited. For non-JWT signatures such as webhook payloads, compare the computed HMAC with `hash_equals()`, never `==` or `===`.

## Key Principles

- Always wrap the verification key in `new Key($keyMaterial, 'RS256')` (or the specific expected algorithm) before passing it to `JWT::decode()` - never pass a bare key string
- For `kid`-based key rotation, pass an associative array of `Key` objects (`['kid1' => new Key($key1, 'RS256'), ...]`) resolved from a trusted, server-side keystore - never build this array from unverified token contents
- Never disable or omit algorithm binding; upgrade off any pre-6.0.0 `firebase/php-jwt` version, which is directly exploitable as CVE-2021-46743
- The upgrade is not a drop-in replacement: the old three-argument form `JWT::decode($jwt, $key, ['RS256'])` fails on 6.0.0+ because the third parameter was repurposed to a by-reference `&$headers` output, so the call now raises `Error: Argument #3 ($headers) could not be passed by reference` rather than silently misbehaving - every call site needs rewriting to the `Key`-object form, not just the dependency bump
- Switching to a `kid`-indexed array of `Key` objects requires every token to carry a `kid` header - a token without one throws `"kid" empty, unable to lookup correct key"`, so confirm the issuer sets `kid` before migrating, or keep the single-`Key` form for a single-key setup
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
