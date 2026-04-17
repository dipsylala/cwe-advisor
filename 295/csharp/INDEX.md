# CWE-295: Improper Certificate Validation - C# / .NET

## LLM Guidance

Improper certificate validation in C# occurs when `HttpClientHandler.ServerCertificateCustomValidationCallback` is set to a lambda that returns `true` unconditionally, or when `ServicePointManager.ServerCertificateValidationCallback` (legacy .NET Framework) is assigned a bypass. These patterns disable TLS certificate chain and hostname verification, exposing all HTTPS traffic to man-in-the-middle attacks. Remove the callback entirely to restore the default PKI validation, or implement a callback that only accepts certificates from a trusted internal CA.

## Key Principles

- Never set `ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true`
- Remove `ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, err) => true` entirely
- For internal CA certificates, validate against the specific CA thumbprint rather than bypassing all checks
- Use `HttpClient` without a custom handler — the default validates against the Windows/system certificate store
- `HttpClientHandler.DangerousAcceptAnyServerCertificateValidator` is named "Dangerous" intentionally — never use it in production

## Remediation Steps

- Search for `ServerCertificateCustomValidationCallback` returning `true` or ignoring the `errors` parameter
- Remove the callback assignment; `HttpClient` validates correctly by default
- For internal CA: add the CA certificate to the Windows Trusted Root store, or load it into an `X509Store` and build a custom callback that verifies the chain against that store
- Replace `ServicePointManager` usage with `HttpClient` + `HttpClientHandler` (required for .NET Core / .NET 5+)
- Test that connections to hosts with untrusted certificates now throw `HttpRequestException` with an inner `AuthenticationException`

## Safe Pattern

```csharp
using System.Net.Http;

// SAFE: no custom callback — certificate validation uses system trust store
var client = new HttpClient();
var response = await client.GetAsync("https://api.example.com/data");

// SAFE: custom internal CA — validate thumbprint, don't bypass
var handler = new HttpClientHandler();
handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
{
    if (errors == System.Net.Security.SslPolicyErrors.None)
        return true;  // Standard validation passed

    // Accept only if it's our known internal CA thumbprint
    const string internalCaThumbprint = "AABBCCDDEEFF...";  // SHA-1 hex, uppercase no spaces
    return cert?.Thumbprint?.Equals(internalCaThumbprint, StringComparison.OrdinalIgnoreCase) == true;
};
var clientWithInternalCA = new HttpClient(handler);
```
