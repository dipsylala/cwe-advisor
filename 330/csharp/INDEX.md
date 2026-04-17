# CWE-330: Use of Insufficiently Random Values - C# / .NET

## LLM Guidance

`System.Random` is a seeded PRNG that produces predictable sequences; it must never be used for security-sensitive values. The correct replacement is `System.Security.Cryptography.RandomNumberGenerator` (or its static helper methods available from .NET 6+). `RandomNumberGenerator.GetBytes()`, `RandomNumberGenerator.GetHexString()`, and `RandomNumberGenerator.GetInt32()` source entropy from the OS cryptographic provider.

## Key Principles

- Replace all `new Random()` or `Random.Shared` usage in security contexts with `RandomNumberGenerator` methods
- Use `RandomNumberGenerator.GetBytes(byte[])` for raw entropy or `Convert.ToBase64String()` / `Convert.ToHexString()` for encoded tokens
- Never use `new Random(seed)` with a predictable seed (timestamp, `Environment.TickCount`) for security purposes
- Generate at least 128 bits (16 bytes) for tokens; 256 bits (32 bytes) for keys
- `Guid.NewGuid()` is not a cryptographically secure random source — do not use it as a security token

## Remediation Steps

- Locate `new Random()` or `Random.Shared.Next()` calls in token generation, key derivation, or nonce creation
- Replace with `RandomNumberGenerator.GetBytes(int count)` (.NET 6+) or `RandomNumberGenerator.Fill(Span<byte>)`
- Encode the byte array as a token using `Convert.ToBase64String()` or `Convert.ToHexString()`
- For integer ranges (OTP, PIN), use `RandomNumberGenerator.GetInt32(int toExclusive)` (.NET 6+)
- Search for `using System; ... new Random()` across the codebase and audit each usage
- Verify tests don't rely on predictable seeding of random generators under test

## Safe Pattern

```csharp
using System.Security.Cryptography;

// 256-bit base64url token (.NET 6+)
public static string GenerateToken()
{
    byte[] bytes = RandomNumberGenerator.GetBytes(32);
    return Convert.ToBase64String(bytes)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');
}

// Hex token (.NET 5+)
public static string GenerateHexToken(int byteLength = 32)
{
    byte[] bytes = RandomNumberGenerator.GetBytes(byteLength);
    return Convert.ToHexString(bytes).ToLowerInvariant();
}

// 6-digit OTP (.NET 6+)
public static int GenerateOtp()
{
    return RandomNumberGenerator.GetInt32(100_000, 1_000_000);
}
```
