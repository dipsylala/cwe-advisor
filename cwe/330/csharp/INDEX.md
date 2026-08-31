# CWE-330: Use of Insufficiently Random Values - C#

## LLM Guidance

`System.Random` is a general-purpose PRNG and must not produce security-sensitive values; the replacement is `System.Security.Cryptography.RandomNumberGenerator`, whose static members Microsoft names as "the preferred way to generate random values". The subtler half of this finding is the GUID: `Guid.NewGuid()` *is* CSPRNG-backed, so the reason to reject it as a token is its 122-bit ceiling and its six fixed version and variant bits, not a weak source. Check the target framework as you go, because these APIs arrived across five different releases.

## Key Principles

- Replace `new Random()` and `Random.Shared` in security contexts with `RandomNumberGenerator`. `Random.Shared` is .NET 6+ and its documentation says only that it is "a thread-safe Random instance" - it carries no security note of its own, so a reviewer looking there finds nothing
- The static helpers have three different floors, and citing one floor for all of them is wrong: `GetInt32` is .NET Core 3.0 / netstandard 2.1, `Fill(Span<byte>)` is .NET Core 2.1, `GetBytes(int)` is .NET 6, and `GetHexString`, `GetString`, `GetItems` and `Shuffle` are .NET 8. `GetBytes(byte[])` is not static at all - it is an instance member needing `RandomNumberGenerator.Create()`
- `Guid.NewGuid()` uses `CoCreateGuid` on Windows and, from .NET 6 on other platforms, the OS CSPRNG; Microsoft documents "122 bits of strong entropy" and recommends against it for cryptographic purposes because a v4 UUID's partially predictable bit pattern makes it unfit as a PRF and because 122 falls below the 128-bit floor policies commonly set. Before .NET 6 the non-Windows entropy was not guaranteed to come from a CSPRNG, which is a real version finding
- `Guid.CreateVersion7()` is .NET 9+. It starts from `NewGuid()` and overwrites the leading 48 bits with a `UtcNow` millisecond timestamp, leaving 74 random bits - sortable and not secret
- `RandomNumberGenerator.GetInt32` is the bounded-integer API precisely because, in Microsoft's words, it "uses a discard-and-retry strategy to avoid the low value bias that a simple modular arithmetic operation would produce". Deriving an OTP with `BitConverter.ToInt32(bytes) % 1_000_000` reintroduces that bias and can yield a negative value. Note the upper bound is exclusive, so `GetInt32` can never return `Int32.MaxValue`
- Generate at least 128 bits (16 bytes) for tokens; size keys by their algorithm
- A JWT HMAC signing key needs its own floor: `Microsoft.IdentityModel.Tokens`'s `SymmetricSecurityKey` only rejects a key under 128 bits (`IDX10653`), but RFC 7518 requires a key at least as large as the hash output - 256 bits for HS256 - so a 16-byte key clears the library's check and still falls short of the spec. Generate 32 bytes with `RandomNumberGenerator.GetBytes(32)`, not the library's own floor

## Taint Sinks

`new Random(`, `Random.Shared`, `Guid.NewGuid()` used as a security token, `Guid.CreateVersion7()` used as a security token, `BitConverter.ToInt32` feeding a modulo

## Remediation Steps

- Locate the weak source. Search separately for `new Random(` and `Random.Shared`, and do not rely on a namespace qualifier: `RandomNumberGenerator` lives in `System.Security.Cryptography`, so `using System;` is not a precondition for the finding, and `new System.Random()` or an implicit global using both evade a pattern anchored on the import
- Audit each `Guid` factory in authentication, reset-token, API-key, nonce and session-ID code, reading which factory the finding names. `NewGuid()` flagged as a weak random *source* is a false positive on the source and a fair point about the 122-bit ceiling; `CreateVersion7()` is a genuine finding for a secret, because half the value is a timestamp
- Replace with `RandomNumberGenerator.GetBytes(int)` or `Fill(Span<byte>)`, and use `GetInt32(fromInclusive, toExclusive)` for OTPs and PINs rather than reducing bytes yourself
- Encode with `System.Buffers.Text.Base64Url` (.NET 9, or earlier through `Microsoft.Bcl.Memory`) or, in ASP.NET Core, `WebEncoders.Base64UrlEncode`, which has shipped since 1.0. Hand-rolling the `+`/`/` to `-`/`_` substitution and stripping padding is reimplementing a shipped API. `Convert.ToHexString` (.NET 5+) returns uppercase
- Check whether the framework already generates the value before writing a generator at all. ASP.NET Core Identity produces its security stamp and authenticator key as 160 bits of base32 over `RandomNumberGenerator.Fill`, issues password-reset and email-confirmation tokens through `DataProtectorTokenProvider`, and mints 128-bit antiforgery tokens internally. A hand-rolled token beside any of these is usually the finding
- Do not treat a fixed seed as the defect to remove. `System.Random`'s parameterless constructor has used xoshiro256\*\* with a thread-static seed since .NET 6, so its output looks fine and is still unsuitable; the defect is the type, not the seed. Reject the reflex fix of a "more random" seed, `new Random(Guid.NewGuid().GetHashCode())`: `GetHashCode()` collapses the GUID into the 32-bit `int` range and the algorithm stays deterministic and brute-forceable
