# CWE-295: Improper Certificate Validation - Java

## LLM Guidance

Improper certificate validation in Java occurs when code replaces the default `TrustManager` with an implementation that accepts all certificates, disables hostname verification on `HttpsURLConnection`, or configures an `SSLContext` with a no-op `X509TrustManager`. These patterns are common in development workarounds that make it into production. The fix is to remove all custom trust managers and hostname verifiers and rely on the JVM's default PKI validation.

## Key Principles

- Never implement `X509TrustManager` with empty `checkServerTrusted` / `checkClientTrusted` methods
- Never set `HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true)`
- Remove any `SSLContext` initialized with a trust-all `TrustManager` array
- For custom CA certificates (internal PKI), import the CA into a `KeyStore` and build a `TrustManagerFactory` from it — do not disable validation
- Use `HttpClient` (Java 11+) with default SSL configuration; it validates certificates by default

## Remediation Steps

- Search for `TrustManager` implementations with empty or `// TODO` method bodies and remove them
- Remove any `HostnameVerifier` that returns `true` unconditionally; delete the `setDefaultHostnameVerifier` call
- Remove `SSLContext.init(null, trustAllCerts, null)` patterns
- For internal CAs, load the CA certificate into a `KeyStore` and configure a `TrustManagerFactory.getInstance("PKIX")`
- Replace `HttpsURLConnection` workarounds with `HttpClient.newHttpClient()` (Java 11+) which uses the JVM default trust store
- Test that connections to hosts with invalid or self-signed certificates now throw `SSLHandshakeException`

## Safe Pattern

```java
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;

// SAFE: default HttpClient validates certificates against the JVM trust store
HttpClient client = HttpClient.newHttpClient();
HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create("https://api.example.com/data"))
    .build();
HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

// SAFE: custom CA (internal PKI) without disabling validation
KeyStore ks = KeyStore.getInstance("JKS");
ks.load(new FileInputStream("internal-ca.jks"), "password".toCharArray());
TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
tmf.init(ks);
SSLContext sslContext = SSLContext.getInstance("TLS");
sslContext.init(null, tmf.getTrustManagers(), null);
HttpClient clientWithCustomCA = HttpClient.newBuilder()
    .sslContext(sslContext)
    .build();
```
