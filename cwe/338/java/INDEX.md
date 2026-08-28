# CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - Java

## LLM Guidance

Java's `java.util.Random` and `Math.random()` are predictable and unsuitable for security operations like generating tokens, keys, or passwords. Attackers can predict outputs and compromise security-sensitive values. Always use `java.security.SecureRandom` for cryptographic purposes.

## Key Principles

- Replace all `java.util.Random` and `Math.random()` with `SecureRandom` in security-sensitive contexts
- Use the default `new SecureRandom()`, `SecureRandom.getInstanceStrong()` where blocking is acceptable, or `DRBG` on Java 9+ when a specific approved DRBG is required
- Initialize `SecureRandom` once and reuse the instance to avoid performance overhead
- Never seed `SecureRandom` with predictable values (timestamps, constants)
- Ensure sufficient entropy by relying on OS-level random sources
- Fill a byte array with `SecureRandom.nextBytes()` sized to the purpose rather than composing a value from `nextInt()` calls, which is easy to bias
- `ThreadLocalRandom.current()` is a performance helper for non-security work and is not a CSPRNG

## Taint Sinks

`new Random()`, `Math.random()`

## Remediation Steps

- Identify all random number generation in security-sensitive code (tokens, keys, salts, IVs, nonces)
- Replace `new Random()` with `new SecureRandom()` or `SecureRandom.getInstanceStrong()`
- Replace `Math.random()` calls with `SecureRandom.nextDouble()` or equivalent methods
- Remove any manual seeding with `setSeed()` unless using truly random entropy
- Validate that the default provider offers cryptographic strength for your platform
- Test for performance impact and optimize instance reuse if needed
