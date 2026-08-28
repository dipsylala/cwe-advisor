# CWE-295: Improper Certificate Validation - C#

## LLM Guidance

Improper certificate validation in C# occurs when `HttpClientHandler.ServerCertificateCustomValidationCallback` is set to a lambda that returns `true` unconditionally, or when `ServicePointManager.ServerCertificateValidationCallback` (legacy .NET Framework) is assigned a bypass. These patterns disable TLS certificate chain and hostname verification, exposing all HTTPS traffic to man-in-the-middle attacks. Remove the callback entirely to restore the default PKI validation, or implement a callback that only accepts certificates from a trusted internal CA.

## Key Principles

- Never set `ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true`
- Remove `ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, err) => true` entirely
- For internal CA certificates, install the CA into the trust store or validate a custom chain and hostname explicitly
- Use `HttpClient` without a custom handler - the default validates against the Windows/system certificate store
- `HttpClientHandler.DangerousAcceptAnyServerCertificateValidator` is named "Dangerous" intentionally - never use it in production

## Taint Sinks

`ServerCertificateCustomValidationCallback` returning `true`, `ServicePointManager.ServerCertificateValidationCallback`, `HttpClientHandler.DangerousAcceptAnyServerCertificateValidator`

## Remediation Steps

- Search for `ServerCertificateCustomValidationCallback` returning `true` or ignoring the `errors` parameter
- Remove the callback assignment; `HttpClient` validates correctly by default
- For internal CA: add the CA certificate to the Windows Trusted Root store, or build an `X509Chain` with `ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust`, the CA added to `ChainPolicy.CustomTrustStore`, and `RevocationMode = X509RevocationMode.Online`
- A custom chain build does not check the hostname, so the callback must still reject `SslPolicyErrors.RemoteCertificateNameMismatch` and return `true` immediately when `errors == SslPolicyErrors.None`
- Replace `ServicePointManager` usage with `HttpClient` + `HttpClientHandler` (required for .NET Core / .NET 5+)
- Test that connections to hosts with untrusted certificates now throw `HttpRequestException` with an inner `AuthenticationException`
