# CWE-295: Improper Certificate Validation - C#

## LLM Guidance

Improper certificate validation in C# occurs when `HttpClientHandler.ServerCertificateCustomValidationCallback` is set to a lambda that returns `true` unconditionally, or when `ServicePointManager.ServerCertificateValidationCallback` is assigned a bypass. The latter is not purely legacy: it is documented from .NET Framework 2.0 through current .NET, and since .NET 9 it is mapped onto `SocketsHttpHandler.SslOptions.RemoteCertificateValidationCallback`, so a global bypass set through it reaches modern `HttpClient` traffic again. These patterns disable TLS certificate chain and hostname verification, exposing all HTTPS traffic to man-in-the-middle attacks. Remove the callback entirely to restore the default PKI validation, or implement a callback that only accepts certificates from a trusted internal CA.

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
- For internal CA: add the CA certificate to the Windows Trusted Root store, or build an `X509Chain` with `ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust` (.NET 5+ only - on .NET Framework or .NET Core 3.x, add the CA to `ChainPolicy.ExtraStore` instead and check `X509ChainStatusFlags.UntrustedRoot` is the only remaining status), the CA added to `ChainPolicy.CustomTrustStore`, and `RevocationMode` left at its documented default of `X509RevocationMode.Online`
- A custom chain build does not check the hostname, so the callback must still reject `SslPolicyErrors.RemoteCertificateNameMismatch` and return `true` immediately when `errors == SslPolicyErrors.None`
- Replace `ServicePointManager` usage with `HttpClient` + `HttpClientHandler` where possible - it remains a global, process-wide setting even where it still works
- Test that connections to hosts with untrusted certificates now throw `HttpRequestException` with an inner `AuthenticationException`
