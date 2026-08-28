# CWE-330: Use of Insufficiently Random Values - Java

## LLM Guidance

`java.util.Random` and `Math.random()` are seeded PRNGs unsuitable for security operations; their output can be predicted if the seed is known. For security-sensitive values (session tokens, API keys, password reset tokens, OTP codes), always use `java.security.SecureRandom`, which sources entropy from the OS.

## Key Principles

- Replace all `new Random()` and `Math.random()` in security contexts with `SecureRandom`
- Use `SecureRandom.getInstanceStrong()` for key generation; use `new SecureRandom()` for high-throughput token generation
- Do not manually seed `SecureRandom` with `setSeed()` unless adding to the existing entropy pool
- Generate at least 128 bits (16 bytes) for tokens; 256 bits (32 bytes) for cryptographic keys
- Encode output in Base64URL or hex before storage or transmission
- `UUID.randomUUID()` draws from `SecureRandom` and carries 122 random bits - adequate as an identifier, short of the usual bar for key material
- Ask for `"DRBG"` where a NIST DRBG is required and `getInstanceStrong()` where a blocking source is wanted; naming a legacy algorithm such as `"SHA1PRNG"` selects an implementation rather than strengthening it
- `nextLong()` yields 64 bits whatever the generator - size the request to the purpose rather than assuming one call is enough

## Taint Sinks

`new Random()`, `Math.random()`

## Remediation Steps

- Locate `new Random()` and `Math.random()` calls in security-sensitive paths (token generation, OTP, key derivation)
- Replace with a shared `SecureRandom` instance (thread-safe; safe to reuse)
- Call `secureRandom.nextBytes(byte[])` to fill a buffer, then encode with `Base64.getUrlEncoder().withoutPadding().encodeToString()`
- For integer ranges (OTP), use `secureRandom.nextInt(bound)` instead of `random.nextInt(bound)`
- Verify all call sites - search for `import java.util.Random` across the codebase
- Run tests to confirm generated values are not sequential or predictable across restarts
