# CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - Java

## LLM Guidance

Java's `java.util.Random` and `Math.random()` are predictable and unsuitable for security operations like generating tokens, keys, or passwords. Attackers can predict outputs and compromise security-sensitive values. Always use `java.security.SecureRandom` for cryptographic purposes - but the trap here is not choosing `SecureRandom`, it is reaching for `getInstanceStrong()` by default, which has hung production systems.

## Key Principles

- Replace all `java.util.Random` and `Math.random()` with `SecureRandom` in security-sensitive contexts
- Use `new SecureRandom()` as the default, not `getInstanceStrong()`. `getInstanceStrong()` resolves to a source that reads `/dev/random` on Linux and has hung indefinitely in production when combined with a bounded `nextInt()` call (a JDK bug report titled "SecureRandom#nextInt(29) does not return" reproduces it on Ubuntu, noting "Executes fine on Windows"). Reserve `getInstanceStrong()` for one-off generation of long-lived key material outside a request path, which is what its own Javadoc describes; `DRBG` (Java 9+, JEP 273) is the choice only when a specific approved DRBG algorithm is required
- Initialize `SecureRandom` once and reuse the instance to avoid performance overhead
- `setSeed()` supplements rather than replaces the existing seed and never reduces randomness by itself - the Javadoc's actual hazard is narrower: a PRNG `SecureRandom` will not seed itself automatically if `setSeed` is called before the first `nextBytes` call, so a fresh instance seeded with a predictable value before first use has exactly that predictable seed and no more. Blanket removal of every `setSeed()` call is not the fix; check what value was passed and when
- Fill a byte array with `SecureRandom.nextBytes()` sized to the purpose rather than composing a value from `nextInt()` calls, which is easy to bias
- `ThreadLocalRandom.current()` is a performance helper for non-security work and is not a CSPRNG. `RandomStringUtils` (Apache Commons Lang) is the same trap wearing a library name: before `commons-lang3` 3.15.0 its static methods drew from `ThreadLocalRandom`, 3.15.0 switched them to `getInstanceStrong()` and was reported in LANG-1748 as blocking production, and 3.17.0 settled on `secure()`/`secureStrong()`/`insecure()` with `secure()` backed by plain `SecureRandom()` - read the deployed version before deciding whether a `RandomStringUtils.random*()` call is the finding

## Taint Sinks

`new Random()`, `Math.random()`, `ThreadLocalRandom.current()`, `RandomStringUtils.random`, `RandomStringUtils.insecure()`

## Remediation Steps

- Identify all random number generation in security-sensitive code (tokens, keys, salts, IVs, nonces)
- Replace `new Random()` with a shared `new SecureRandom()` held in a reused instance; reach for `getInstanceStrong()` only for one-off long-lived key material generated outside a request or startup path
- Replace `Math.random()` calls with `SecureRandom.nextDouble()` or equivalent methods
- Do not remove every `setSeed()` call on sight - only a call that seeds a fresh instance with a low-entropy value before its first `nextBytes()` is the defect; a `setSeed()` call after normal use is supplementing, not replacing, real entropy
- Check `RandomStringUtils` usage against the `commons-lang3` version in use, since the static `random*()` methods changed backing generator across 3.15.0, 3.16.0 and 3.17.0
- Test for performance impact and optimize instance reuse if needed
