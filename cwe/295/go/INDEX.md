# CWE-295: Improper Certificate Validation - Go

## LLM Guidance

In Go, TLS clients built with `crypto/tls` disable certificate validation when `tls.Config.InsecureSkipVerify` is set to `true`. `VerifyPeerCertificate` and `VerifyConnection` run *after* Go's normal verification unless `InsecureSkipVerify` is also `true` - a weak callback (checking only the subject organization, say) is not itself a bypass when the default validation still ran underneath it. The actual dangerous pattern is the pair together: `InsecureSkipVerify: true` plus a hand-rolled callback that the author believes replaces full chain/hostname/expiry checking but only covers part of it. This is common in `net/http` clients, gRPC dial options, and Kubernetes `client-go` configuration (`rest.TLSClientConfig.Insecure`). The fix is to remove `InsecureSkipVerify` and any compensating callback together, relying on Go's default validation, adding a custom `RootCAs` pool only for private or internal CAs.

## Key Principles

- Never set `InsecureSkipVerify: true` in application code; the zero-value `tls.Config{}` already performs full chain, expiry, and hostname validation
- Treat `VerifyPeerCertificate`/`VerifyConnection` as a bypass only when paired with `InsecureSkipVerify: true` - with it unset, Go's normal verification already ran before the callback fires, so an incomplete callback there is a redundant weak check, not the disabling one
- For internal or private CAs, build a trust pool with `x509.NewCertPool()` and `AppendCertsFromPEM`, or start from `x509.SystemCertPool()` and append to it, then assign the pool to `tls.Config.RootCAs` - on Windows and macOS, `SystemCertPool()` can return an empty, non-nil pool when the platform verifier is used instead, so code that asserts the pool is non-empty before appending will fail there even though verification still works
- Go has set the client-side `MinVersion` default to TLS 1.2 since Go 1.18; setting `tls.Config.MinVersion: tls.VersionTLS12` (prefer TLS 1.3 where compatible) explicitly still matters for a server-side `tls.Config`, whose default floor is unaffected, and for any client built with an older Go toolchain
- For `client-go` (Kubernetes) configs, never set `rest.TLSClientConfig.Insecure = true`; use `rest.InClusterConfig()` in-cluster, or a kubeconfig that does not set `insecure-skip-tls-verify: true`
- Use `httptest.NewTLSServer` and `server.Client()` for HTTPS integration tests instead of disabling verification

## Taint Sinks

`tls.Config{InsecureSkipVerify: true}`, bypassing `VerifyPeerCertificate`/`VerifyConnection`, `rest.TLSClientConfig.Insecure`

## Remediation Steps

- Locate - search for `InsecureSkipVerify`, custom `VerifyPeerCertificate`/`VerifyConnection` functions, and `rest.TLSClientConfig{Insecure: true}`
- Trace data flow - confirm which `http.Client`/`http.Transport`, gRPC dial option, or `client-go` config consumes the affected `tls.Config`
- Replace the unsafe pattern - delete the `InsecureSkipVerify` flag and any bypass callback; let the zero-value `tls.Config` (or one with only `RootCAs`/`MinVersion` set) perform default validation
- Configure trusted CAs - for internal PKI, load the CA into an `x509.CertPool` via `RootCAs` rather than skipping verification
- Harden configuration - set `MinVersion: tls.VersionTLS12` explicitly on any server-side `tls.Config` (the client-side default only rose to 1.2 in Go 1.18) and avoid overriding `ServerName` except to support legitimate SNI/IP-based connection scenarios
- Test - connect to endpoints presenting expired, self-signed, wrong-hostname, and untrusted-chain certificates and confirm the client returns an `x509` verification error instead of connecting
