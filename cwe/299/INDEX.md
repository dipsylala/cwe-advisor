# CWE-299: Improper Check for Certificate Revocation

## LLM Guidance

This weakness occurs when code trusts a certificate without checking whether it has been revoked, allowing a compromised or otherwise invalidated certificate to be accepted. The core fix is to enable revocation checking (OCSP stapling preferred, CRL as fallback) in the TLS configuration and to define an explicit fail behavior for when revocation status cannot be determined.

## Key Principles

- Enable revocation checking (OCSP or CRL) in the TLS or certificate validation configuration; chain and expiration checks alone are not sufficient
- Prefer OCSP stapling over client-initiated OCSP or full CRL downloads for performance and privacy
- Decide and document the fail behavior for indeterminate revocation status (soft-fail vs hard-fail) based on the sensitivity of the connection; use hard-fail for high-value operations
- Do not disable revocation checking to work around network or performance issues without an explicit, reviewed decision
- Cache revocation responses within their stated validity window to avoid excessive network calls without relying on stale data
- Combine revocation checking with chain and expiration validation as an additional layer, not a replacement

## Remediation Steps

- Locate - Find TLS configuration or certificate validation code and confirm whether revocation checking is enabled
- Trace data flow - Identify how the certificate chain reaches the validation logic and whether an OCSP or CRL check is invoked
- Identify the unsafe pattern - Revocation checking disabled, OCSP/CRL errors caught and ignored, or custom validation logic that omits a revocation step
- Replace with the safe pattern - Enable the library's built-in revocation checking (OCSP stapling with CRL fallback) with explicit timeout and fail behavior
- Add secondary controls - Choose hard-fail vs soft-fail per use case, log revocation check outcomes, and monitor OCSP responder availability
- Test - Present a revoked test certificate and confirm rejection; simulate an unreachable OCSP responder and confirm the configured fail behavior triggers correctly
