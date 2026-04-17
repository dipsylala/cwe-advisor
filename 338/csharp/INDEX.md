# CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - C# / .NET

## LLM Guidance

`System.Random` uses a seeded deterministic algorithm and is not cryptographically secure. Using it for tokens, keys, nonces, or session identifiers allows an attacker who observes a few outputs (or knows the seed, often derived from `Environment.TickCount`) to predict all future and past outputs. Replace with `System.Security.Cryptography.RandomNumberGenerator`, which uses the OS cryptographic entropy source.

## Key Principles

- Replace `new Random()` and `Random.Shared.Next()` in security contexts with `RandomNumberGenerator` static methods
- Use `RandomNumberGenerator.GetBytes()` for raw entropy, `GetInt32()` for bounded integers, `GetHexString()` for hex tokens
- Never seed `Random` from timestamp or `Environment.TickCount` for security use — seeded `Random` is reproducible
- `Guid.NewGuid()` is not a suitable security token — it may encode timestamp or MAC address depending on the platform
- Keep `System.Random` only for non-security simulation, gaming, or test data generation

## Remediation Steps

- Search for `new Random()` and `Random.Shared` in authentication, session, token, and key-generation code
- Replace with `RandomNumberGenerator.GetBytes(int count)` (.NET 6+) and encode the result
- For bounded integer generation (OTPs, PINs), use `RandomNumberGenerator.GetInt32(fromInclusive, toExclusive)` (.NET 6+)
- On .NET Framework or .NET 5, use `RandomNumberGenerator.Create()` with `GetBytes(byte[])`
- Confirm `System.Random` import is not pulled into security-sensitive files via `using System;`
- After replacement, test that values are non-repeating and unpredictable across application restarts

## Safe Pattern

```csharp
using System.Security.Cryptography;

// SAFE: cryptographically secure random bytes (.NET 6+)
byte[] token = RandomNumberGenerator.GetBytes(32);
string tokenBase64 = Convert.ToBase64String(token);

// SAFE: hex token (.NET 5+)
string hexToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

// SAFE: secure integer range — OTP between 100000 and 999999
int otp = RandomNumberGenerator.GetInt32(100_000, 1_000_000);

// .NET Framework / .NET 5 fallback
using var rng = RandomNumberGenerator.Create();
byte[] buffer = new byte[32];
rng.GetBytes(buffer);
string legacyToken = Convert.ToBase64String(buffer);
```
