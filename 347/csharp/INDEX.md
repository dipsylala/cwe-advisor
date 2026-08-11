# CWE-347: Improper Verification of Cryptographic Signature - C#

## LLM Guidance

`System.IdentityModel.Tokens.Jwt` and `Microsoft.IdentityModel.Tokens` are vulnerable to algorithm confusion when `TokenValidationParameters` does not restrict `ValidAlgorithms`, allowing an attacker to switch a token from RS256 to HS256 and sign it with the server's RSA public key treated as an HMAC secret. Always set `TokenValidationParameters.ValidAlgorithms` to an explicit array of accepted algorithms and pair it with `ValidateIssuerSigningKey = true`. For non-JWT signatures such as webhook payloads, compare the computed HMAC with `CryptographicOperations.FixedTimeEquals()`, never `==` on a byte array.

## Key Principles

- Always set `TokenValidationParameters.ValidAlgorithms` to a fixed array (for example `new[] { SecurityAlgorithms.RsaSha256 }`) - by default the handler accepts whatever algorithm the token's header declares
- Never build an `IssuerSigningKeyResolver` that returns key material chosen by the unverified token header's `alg`, and never store RSA public keys and HMAC secrets in the same lookup keyed only by `kid`
- Populate `IssuerSigningKey`/`IssuerSigningKeys` only from a trusted, server-side keystore or JWKS - never accept a key embedded in the token (`jwk`/`x5c` headers) without independently verifying it against a pinned trust anchor
- Reject `alg: none` and weak algorithms; `ValidAlgorithms` combined with `RequireSignedTokens = true` prevents unsigned tokens from validating
- Use `CryptographicOperations.FixedTimeEquals()` (.NET Core 2.1+) for any raw signature/HMAC comparison - never `==`, `SequenceEqual()`, or `Array.Equals()`, none of which are constant-time
- Set `ValidateIssuer`, `ValidateAudience`, and `ValidateLifetime` to `true` in addition to signature validation

## Taint Sinks

`JwtSecurityTokenHandler.ValidateToken()` without `ValidAlgorithms`, `IssuerSigningKeyResolver` keyed by header `alg`, `==`/`SequenceEqual()` on signature bytes

## Remediation Steps

- Locate - find `TokenValidationParameters`, `JwtSecurityTokenHandler.ValidateToken()`, `JsonWebTokenHandler.ValidateTokenAsync()`, or custom `HMACSHA256`/`RSA` verification code
- Trace data flow - confirm whether `ValidAlgorithms` is set and whether any custom key resolver reads the token header before key selection
- Replace the unsafe pattern - add `ValidAlgorithms` explicitly; remove any `IssuerSigningKeyResolver` logic that branches on attacker-controlled header values
- Bind, encode, validate, or authorize - resolve signing keys by `kid` only from a trusted keystore, and pin the algorithm the resolved key is allowed to use
- Harden configuration - set `RequireSignedTokens = true`, `RequireExpirationTime = true`, and validate issuer/audience
- Test - re-sign a legitimate RS256 token as HS256 using the known public key as secret and confirm `ValidateToken()` throws `SecurityTokenInvalidSignatureException`

## Safe Pattern

```csharp
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

// SAFE: algorithm is pinned - the token header cannot select HS256 instead
var validationParameters = new TokenValidationParameters
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = rsaSecurityKey,
    ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
    RequireSignedTokens = true,
    ValidateIssuer = true,
    ValidIssuer = "https://issuer.example.com",
    ValidateAudience = true,
    ValidAudience = "my-api",
};
var handler = new JwtSecurityTokenHandler();
var principal = handler.ValidateToken(token, validationParameters, out _);

// SAFE: webhook HMAC-SHA256 verification with constant-time comparison
byte[] expected = new HMACSHA256(webhookSecret).ComputeHash(requestBody);
byte[] provided = Convert.FromHexString(signatureHeader);
if (!CryptographicOperations.FixedTimeEquals(expected, provided))
{
    throw new SecurityException("Invalid webhook signature");
}
```
