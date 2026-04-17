# CWE-330: Use of Insufficiently Random Values - Java

## LLM Guidance

`java.util.Random` and `Math.random()` are seeded PRNGs unsuitable for security operations; their output can be predicted if the seed is known. For security-sensitive values (session tokens, API keys, password reset tokens, OTP codes), always use `java.security.SecureRandom`, which sources entropy from the OS.

## Key Principles

- Replace all `new Random()` and `Math.random()` in security contexts with `SecureRandom`
- Use `SecureRandom.getInstanceStrong()` for key generation; use `new SecureRandom()` for high-throughput token generation
- Do not manually seed `SecureRandom` with `setSeed()` unless adding to the existing entropy pool
- Generate at least 128 bits (16 bytes) for tokens; 256 bits (32 bytes) for cryptographic keys
- Encode output in Base64URL or hex before storage or transmission

## Remediation Steps

- Locate `new Random()` and `Math.random()` calls in security-sensitive paths (token generation, OTP, key derivation)
- Replace with a shared `SecureRandom` instance (thread-safe; safe to reuse)
- Call `secureRandom.nextBytes(byte[])` to fill a buffer, then encode with `Base64.getUrlEncoder().withoutPadding().encodeToString()`
- For integer ranges (OTP), use `secureRandom.nextInt(bound)` instead of `random.nextInt(bound)`
- Verify all call sites — search for `import java.util.Random` across the codebase
- Run tests to confirm generated values are not sequential or predictable across restarts

## Safe Pattern

```java
import java.security.SecureRandom;
import java.util.Base64;

public class TokenGenerator {
    // Thread-safe; reuse the instance
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // 256-bit URL-safe token
    public static String generateToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // 6-digit OTP
    public static int generateOtp() {
        return SECURE_RANDOM.nextInt(900_000) + 100_000;
    }
}
```
