# CWE-297: Improper Validation of Certificate with Host Mismatch

## LLM Guidance

Improper certificate hostname validation occurs when TLS/SSL clients don't verify the certificate's Common Name (CN) or Subject Alternative Name (SAN) matches the hostname being connected to. This enables man-in-the-middle attacks by allowing attackers to present valid certificates for different domains.

## Key Principles

- Never establish a TLS connection unless the certificate's hostname is validated against the requested peer identity
- Applications must not bypass or weaken hostname verification (avoid SSL_VERIFY_NONE, check_hostname=False)
- Use default SSL/TLS library configurations which enable hostname verification by default
- Custom certificate validators must explicitly check CN/SAN fields against the target hostname
- Hostname verification is separate from certificate chain validation-both are required
- Raw TLS sockets skip the name check by default, with nothing disabled and no `verify=False` for a rule to match: a Java `SSLSocket` and a Python `SSLContext.wrap_socket()` called without `server_hostname` both verify the chain and authenticate nobody. Set `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")` before `startHandshake()`, and pass `server_hostname=host` in Python
- In OpenSSL the name check is opt-in rather than a switch: `SSL_VERIFY_PEER` alone gives a fully validated chain with no name check at all, so call `SSL_set1_host()` or `X509_VERIFY_PARAM_set1_host()`
- Removing the chain-verification switches (`verify=False`, `ssl.CERT_NONE`, `SSL_VERIFY_NONE`) is necessary and does not by itself give a name check; the hostname switches are separate - a `HostnameVerifier` returning `true`, Apache HttpClient's `NoopHostnameVerifier.INSTANCE` (named `ALLOW_ALL_HOSTNAME_VERIFIER` through the 4.5.x line, gone in 5.x), `check_hostname = False`, and `assert_hostname=False`

## Remediation Steps

- Locate the vulnerability - Review flaw details for specific file, line number, and code pattern where hostname verification is disabled or weakened
- Identify bypass patterns - Search for SSL_VERIFY_NONE, check_hostname=False, InsecureRequestWarning suppressions, or custom validators
- Enable default verification - Use standard library defaults with hostname checking enabled (e.g., requests with verify=True, Python ssl with check_hostname=True)
- Remove verification bypasses - Delete or refactor any code that disables certificate or hostname validation
- Test secure connections - Verify connections fail appropriately with invalid/mismatched certificates
- Review all TLS clients - Audit entire codebase for similar patterns in other connection points
