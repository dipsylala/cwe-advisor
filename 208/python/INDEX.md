# CWE-208: Observable Timing Discrepancy - Python

## LLM Guidance

In Python, timing discrepancies typically appear when secrets (password hashes, HMAC digests, API tokens, session IDs) are compared with the standard `==` operator on `str` or `bytes`, which short-circuits at the first mismatched byte. Use `hmac.compare_digest()` for any comparison involving a secret - it accepts `str` or `bytes` and always compares the full length regardless of where a mismatch occurs. Most higher-level libraries (HMAC verification helpers, JWT libraries) already use constant-time comparison internally; the risk is in hand-rolled checks.

## Key Principles

- Use `hmac.compare_digest(a, b)` for any comparison involving a secret value, never `==` or `!=`
- Both arguments must be the same type (both `str` or both `bytes`); mixing types raises `TypeError`, so encode/decode consistently before comparing
- Prefer comparing `bytes` over `str` for the strongest guarantee, since `bytes` comparison is the primary case the implementation is hardened for
- Do not attempt a custom constant-time comparison with a manual loop and bitwise operators - `hmac.compare_digest()` is already correct and less error-prone
- Apply this to every secret comparison: password hashes, HMAC signatures, API keys, session tokens, CSRF tokens

## Taint Sinks

`==`/`!=` used to compare a secret value (password hash, HMAC digest, API key, session token)

## Remediation Steps

- Locate - find comparisons of secret values (password hashes, tokens, HMAC digests) using `==` or `!=`
- Trace data flow - confirm the value comes from a security-sensitive source (stored credential, computed HMAC, session store)
- Replace with the safe pattern - use `hmac.compare_digest(a, b)` in place of `==`
- Match types before comparing - ensure both operands are `bytes` (preferred) or both `str`
- Test - verify the comparison still returns the correct boolean for matching and non-matching inputs, and confirm no custom timing-sensitive logic remains
