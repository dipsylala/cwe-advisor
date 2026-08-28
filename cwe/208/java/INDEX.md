# CWE-208: Observable Timing Discrepancy - Java

## LLM Guidance

In Java, timing discrepancies typically appear when secrets (password hashes, HMAC digests, API tokens) are compared with `String.equals()`, `Arrays.equals()`, or `==`, all of which return as soon as they find a differing byte or character. Use `java.security.MessageDigest.isEqual(byte[], byte[])` for any comparison involving a secret - since JDK 6u17 it is documented to run in time dependent only on the length of the arrays, not their content. Frameworks like Spring Security's password encoders already use constant-time comparison internally; the risk is in manual HMAC/signature verification and hand-rolled token checks.

## Key Principles

- Use `MessageDigest.isEqual(byte[], byte[])` for any comparison involving a secret, never `String.equals()`, `Arrays.equals()`, or `==`
- Convert secrets to `byte[]` using a consistent encoding (e.g. UTF-8) on both sides before comparing
- Do not write a custom constant-time comparison loop - `MessageDigest.isEqual()` already provides this and is less error-prone
- Apply this to every secret comparison: password hashes, HMAC signatures, API keys, session tokens, CSRF tokens
- `MessageDigest.isEqual()` still returns early on unequal-length inputs - acceptable for typical fixed-length secrets like hashes and HMAC digests, but avoid designing a scheme where the length itself must stay secret
- Spring Security's `DaoAuthenticationProvider` hashes against a dummy encoded password when the user is not found, which is what keeps the unknown-username path the same cost as the wrong-password path - preserve that behaviour if you replace the provider or short-circuit the lookup
- Report a single `BadCredentialsException` for unknown user and wrong password alike; `DisabledException` and `LockedException` from an `AccountStatusUserDetailsChecker` disclose that the account exists, so map them to the generic failure at the boundary
- `PasswordEncoder.matches()` is constant-time for the digest comparison, so the remaining leak is the surrounding control flow rather than the comparison

## Taint Sinks

`String.equals()`, `Arrays.equals()`, `==` used to compare a secret value (password hash, HMAC digest, API key, session token)

## Remediation Steps

- Locate - find comparisons of secret values (password hashes, tokens, HMAC digests) using `.equals()`, `Arrays.equals()`, or `==`
- Trace data flow - confirm the value comes from a security-sensitive source (stored credential, computed HMAC, session store)
- Replace with the safe pattern - convert both values to `byte[]` and use `MessageDigest.isEqual(a, b)`
- Test - verify the comparison still returns the correct boolean for matching and non-matching inputs
