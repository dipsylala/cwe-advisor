# CWE-295: Improper Certificate Validation - Java

## LLM Guidance

Improper certificate validation in Java occurs when code replaces the default `TrustManager` with an implementation that accepts all certificates, disables hostname verification on `HttpsURLConnection`, or configures an `SSLContext` with a no-op `X509TrustManager`. These patterns are common in development workarounds that make it into production. The fix is to remove all custom trust managers and hostname verifiers and rely on the JVM's default PKI validation.

## Key Principles

- Never implement `X509TrustManager` with empty `checkServerTrusted` / `checkClientTrusted` methods
- Never set `HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true)`
- Remove any `SSLContext` initialized with a trust-all `TrustManager` array
- For custom CA certificates (internal PKI), import the CA into a `KeyStore` and build a `TrustManagerFactory` from it - do not disable validation
- Use `HttpClient` (Java 11+) with default SSL configuration; it validates certificates by default

## Taint Sinks

`X509TrustManager.checkServerTrusted()` (empty body), `HttpsURLConnection.setDefaultHostnameVerifier()` returning `true`, `SSLContext.init()` with trust-all managers

## Remediation Steps

- Search for `TrustManager` implementations with empty or `// TODO` method bodies and remove them
- Remove any `HostnameVerifier` that returns `true` unconditionally; delete the `setDefaultHostnameVerifier` call
- Remove `SSLContext.init(null, trustAllCerts, null)` patterns
- For internal CAs, load the CA certificate into a `KeyStore`, configure a `TrustManagerFactory.getInstance("PKIX")`, pass its `getTrustManagers()` to `SSLContext.init(null, ..., null)`, and attach it with `HttpClient.newBuilder().sslContext(...)`
- Replace `HttpsURLConnection` workarounds with `HttpClient.newHttpClient()` (Java 11+) which uses the JVM default trust store
- Test that connections to hosts with invalid or self-signed certificates now throw `SSLHandshakeException`
