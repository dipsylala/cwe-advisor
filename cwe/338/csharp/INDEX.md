# CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - C#

## LLM Guidance

`System.Random` uses a seeded deterministic algorithm and is not cryptographically secure. Microsoft documents its parameterless constructor as seeding from the system clock, so an attacker who observes a few outputs (or can narrow the process start time) can predict all future and past outputs. Replace with `System.Security.Cryptography.RandomNumberGenerator`, which uses the OS cryptographic entropy source.

## Key Principles

- Replace `new Random()` and `Random.Shared.Next()` in security contexts with `RandomNumberGenerator` static methods
- Use `RandomNumberGenerator.GetBytes()` (.NET 6+) for raw entropy, `GetInt32()` (.NET Core 3.0+) for bounded integers, `GetHexString()` (.NET 8+) for hex tokens - these arrived across three different releases, so check the target framework before citing one floor for all of them
- Never seed `Random` from a timestamp or a low-entropy value for security use - seeded `Random` is reproducible
- `Guid.NewGuid()` is not a suitable security token - UUIDv4 values have fixed bits, at most 122 bits of entropy, and are not cryptographic PRFs
- Keep `System.Random` only for non-security simulation, gaming, or test data generation

## Taint Sinks

`new Random()`, `Random.Shared.Next()`, `Guid.NewGuid()` (as a security token)

## Remediation Steps

- Search for `new Random()` and `Random.Shared` in authentication, session, token, and key-generation code
- Replace with `RandomNumberGenerator.GetBytes(int count)` (.NET 6+) and encode the result with `Convert.ToBase64String()` or `Convert.ToHexString()`
- For bounded integer generation (OTPs, PINs), use `RandomNumberGenerator.GetInt32(fromInclusive, toExclusive)` (.NET Core 3.0+)
- On .NET Framework or .NET 5, use `RandomNumberGenerator.Create()` with `GetBytes(byte[])`
- Confirm `System.Random` import is not pulled into security-sensitive files via `using System;`
- After replacement, test that values are non-repeating and unpredictable across application restarts
