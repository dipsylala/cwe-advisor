# CWE-295: Improper Certificate Validation - Go

## LLM Guidance

In Go, TLS clients built with `crypto/tls` disable certificate validation when `tls.Config.InsecureSkipVerify` is set to `true`, or when a custom `VerifyPeerCertificate`/`VerifyConnection` callback checks only part of the certificate (for example the subject organization) instead of the full chain, expiry, and hostname. This is common in `net/http` clients, gRPC dial options, and Kubernetes `client-go` configuration (`rest.TLSClientConfig.Insecure`). The fix is to remove the bypass and rely on Go's default validation, adding a custom `RootCAs` pool only for private or internal CAs.

## Key Principles

- Never set `InsecureSkipVerify: true` in application code; the zero-value `tls.Config{}` already performs full chain, expiry, and hostname validation
- Remove any `VerifyPeerCertificate` or `VerifyConnection` callback that unconditionally returns `nil` or checks only a subset of chain, hostname, or expiry
- For internal or private CAs, build a trust pool with `x509.NewCertPool()` and `AppendCertsFromPEM`, or start from `x509.SystemCertPool()` and append to it, then assign the pool to `tls.Config.RootCAs`
- Set `tls.Config.MinVersion: tls.VersionTLS12` (prefer TLS 1.3 where compatible) alongside certificate checks to reject downgraded handshakes
- For `client-go` (Kubernetes) configs, never set `rest.TLSClientConfig.Insecure = true`; use `rest.InClusterConfig()` in-cluster, or a kubeconfig that does not set `insecure-skip-tls-verify: true`
- Use `httptest.NewTLSServer` and `server.Client()` for HTTPS integration tests instead of disabling verification

## Taint Sinks

`tls.Config{InsecureSkipVerify: true}`, bypassing `VerifyPeerCertificate`/`VerifyConnection`, `rest.TLSClientConfig.Insecure`

## Remediation Steps

- Locate - search for `InsecureSkipVerify`, custom `VerifyPeerCertificate`/`VerifyConnection` functions, and `rest.TLSClientConfig{Insecure: true}`
- Trace data flow - confirm which `http.Client`/`http.Transport`, gRPC dial option, or `client-go` config consumes the affected `tls.Config`
- Replace the unsafe pattern - delete the `InsecureSkipVerify` flag and any bypass callback; let the zero-value `tls.Config` (or one with only `RootCAs`/`MinVersion` set) perform default validation
- Configure trusted CAs - for internal PKI, load the CA into an `x509.CertPool` via `RootCAs` rather than skipping verification
- Harden configuration - set `MinVersion: tls.VersionTLS12` and avoid overriding `ServerName` except to support legitimate SNI/IP-based connection scenarios
- Test - connect to endpoints presenting expired, self-signed, wrong-hostname, and untrusted-chain certificates and confirm the client returns an `x509` verification error instead of connecting
