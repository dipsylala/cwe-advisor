# CWE-299: Improper Check for Certificate Revocation - Java

## LLM Guidance

Java checks revocation in two places with opposite defaults. The PKIX certification-path API (`CertPathValidator`, `PKIXParameters`) performs revocation checking by default because it is a required step of the algorithm, but supplies no way to *fetch* a status unless the retrieval properties are enabled. JSSE - the TLS stack behind `HttpsURLConnection`, `SSLSocket`, and every HTTP client built on them - does not check revocation at all unless it is turned on. Neither default gives what its name suggests, so enable checking *and* a retrieval mechanism, and do it before the process opens its first TLS connection.

## Key Principles

- For TLS, three settings are needed together: `com.sun.net.ssl.checkRevocation=true` (ask for a status at all), `Security.setProperty("ocsp.enable", "true")` (query the responder named in the Authority Information Access extension), and `com.sun.security.enableCRLDP=true` (fetch the CRL named in the CRL Distribution Point extension). With `checkRevocation` alone, JSSE asks for a status it has no enabled way to fetch and every connection fails with `Could not determine revocation status`
- Set them as JVM flags (`-Dcom.sun.net.ssl.checkRevocation=true`), not at runtime: the value is read once and frozen in a `static final` field the first time the process validates a TLS certificate, and building a fresh `SSLContext` does not re-read it
- `PKIXRevocationChecker` (Java 8+) is the explicit form: it lets you choose `Option.PREFER_CRLS`, `NO_FALLBACK`, and - deliberately, never by default - `SOFT_FAIL`
- Decide the soft-fail policy consciously: `SOFT_FAIL` treats an unreachable responder as success, which is the difference between a revocation check and the appearance of one
- `setRevocationEnabled(false)` on `PKIXParameters` is the explicit disable to look for in an existing codebase, usually added to make a test pass
- OCSP stapling (`jdk.tls.client.enableStatusRequestExtension=true`) avoids the responder round trip and the availability problem it introduces
- Never "fix" a revocation failure with a trust-all `X509TrustManager` or a null `HostnameVerifier` - that removes certificate validation entirely (CWE-295)
- Test against a known-revoked endpoint rather than assuming the configuration took effect; a check that silently does nothing looks identical to one that passed

## Taint Sinks

`SSLContext.init()` with a trust manager that does not check revocation, `PKIXParameters.setRevocationEnabled(false)`, a custom `X509TrustManager` with an empty `checkServerTrusted`, `HttpsURLConnection` with default JSSE settings, `PKIXRevocationChecker.Option.SOFT_FAIL`

## Remediation Steps

- Locate - find `SSLContext`/`TrustManagerFactory` construction, `PKIXParameters` usage, and any custom `X509TrustManager`
- Trace data flow - determine which trust path each client uses, and whether the process sets the revocation properties before its first TLS handshake
- Identify the unsafe pattern - revocation not enabled for JSSE, revocation enabled with no retrieval mechanism, `SOFT_FAIL` accepted implicitly, or a trust-all manager
- Replace with the safe pattern - pass the three JVM flags, or obtain a `PKIXRevocationChecker` from `CertPathValidator.getRevocationChecker()` (it has no public constructor), set its options, and attach it with `addCertPathChecker()`
- Bind, encode, validate, or authorize - make the soft-fail decision explicit and log it, so an unreachable responder is visible rather than silently accepted
- Harden configuration - enable OCSP stapling, set sensible connect and read timeouts on revocation fetches, and remove any test-only trust-all manager from production paths
- Test - connect to a deliberately revoked test endpoint and assert the handshake fails; then connect to a valid endpoint and assert it succeeds
