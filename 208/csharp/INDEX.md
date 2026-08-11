# CWE-208: Observable Timing Discrepancy - C#

## LLM Guidance

In C#, timing discrepancies typically appear when secrets (password hashes, HMAC digests, API tokens) are compared with `==`, `String.Equals()`, or `Enumerable.SequenceEqual()`, none of which are guaranteed constant-time. Use `System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ReadOnlySpan<byte>, ReadOnlySpan<byte>)` (added in .NET Core 2.1) for any comparison involving a secret - it compares two byte spans in constant time relative to their length. ASP.NET Core Identity's password hashers already use constant-time comparison internally; the risk is in manual HMAC/signature verification and hand-rolled token checks.

## Key Principles

- Use `CryptographicOperations.FixedTimeEquals(a, b)` for any comparison involving a secret, never `==`, `String.Equals()`, or `Enumerable.SequenceEqual()`
- Convert secrets to `byte[]` (or `ReadOnlySpan<byte>`) using a consistent encoding (e.g. UTF-8) on both sides before comparing
- `FixedTimeEquals()` returns `false` immediately if the two spans have different lengths, without comparing content - acceptable for typical fixed-length secrets like hashes and HMAC digests, but avoid relying on it where the length itself must stay secret
- Do not write a custom constant-time comparison loop - `CryptographicOperations.FixedTimeEquals()` already provides this and is available in all currently supported .NET versions
- Apply this to every secret comparison: password hashes, HMAC signatures, API keys, session tokens, CSRF tokens

## Taint Sinks

`==`, `String.Equals()`, `Enumerable.SequenceEqual()` used to compare a secret value (password hash, HMAC digest, API key, session token)

## Remediation Steps

- Locate - find comparisons of secret values (password hashes, tokens, HMAC digests) using `==`, `.Equals()`, or `SequenceEqual()`
- Trace data flow - confirm the value comes from a security-sensitive source (stored credential, computed HMAC, session store)
- Replace with the safe pattern - convert both values to `byte[]` and use `CryptographicOperations.FixedTimeEquals(a, b)`
- Test - verify the comparison still returns the correct boolean for matching and non-matching inputs

## Safe Pattern

```csharp
using System.Security.Cryptography;
using System.Text;

// SAFE: constant-time comparison regardless of where the mismatch occurs
public bool VerifyToken(string providedToken, string expectedToken)
{
    byte[] provided = Encoding.UTF8.GetBytes(providedToken);
    byte[] expected = Encoding.UTF8.GetBytes(expectedToken);
    return CryptographicOperations.FixedTimeEquals(provided, expected);
}
```
