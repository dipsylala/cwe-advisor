# CWE-330: Use of Insufficiently Random Values - PHP

## LLM Guidance

Weak random number generation in PHP occurs when insecure functions like `rand()`, `mt_rand()`, or `uniqid()` are used for security-sensitive operations such as generating session tokens, password reset tokens, API keys, or CSRF tokens. These functions use predictable pseudo-random number generators that attackers can exploit. Always use cryptographically secure functions `random_bytes()` and `random_int()` (PHP 7.0+) for any security-related randomness.

## Key Principles

- Replace all instances of `rand()`, `mt_rand()`, `uniqid()`, and `lcg_value()` with `random_int()` or `random_bytes()` in security contexts
- Use `random_bytes()` for generating tokens, keys, and binary random data
- Use `random_int()` for random integers within a specific range
- Never use predictable PRNGs for authentication, authorization, cryptography, or session management
- Verify token length is sufficient (at least 16-32 bytes for security tokens)
- `random_bytes()`/`random_int()` throw rather than returning weak output, which is the property that makes them safe - never catch the exception and fall back to `mt_rand()` or `openssl_random_pseudo_bytes()`
- `openssl_random_pseudo_bytes()` reports its own strength through a by-reference second argument that is easy to omit; prefer `random_bytes()`, which has no weak mode to detect
- `array_rand()` and `str_shuffle()` use the non-cryptographic generator despite having nothing "random" in the risky part of their names
- `password_hash()` generates its own CSPRNG salt - passing one is unnecessary and, done wrongly, harmful

## Taint Sinks

`rand()`, `mt_rand()`, `uniqid()`, `lcg_value()`

## Remediation Steps

- Identify all uses of weak random functions in security-sensitive code paths
- Replace token generation with `bin2hex(random_bytes($length))` or `base64_encode(random_bytes($length))`
- Replace random number generation with `random_int($min, $max)`
- Ensure minimum token length of 32 characters (16 bytes) for session/CSRF tokens
- Test that tokens are unpredictable and unique across multiple generations
- Review and update any cryptographic operations to use secure randomness
