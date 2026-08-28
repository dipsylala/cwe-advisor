# CWE-298: Improper Validation of Certificate Expiration

## LLM Guidance

This weakness occurs when code accepts a certificate without checking its notBefore/notAfter validity window, or when expiration errors are caught and ignored, allowing expired or not-yet-valid certificates to be trusted. The core fix is to use the standard TLS/X.509 library's default validation path, which enforces expiration checks, and to remove any override that suppresses or bypasses date validation errors.

## Key Principles

- Use the standard TLS/X.509 library's expiration check; never catch and discard date-validation exceptions
- Never configure clients or servers to accept expired certificates, including in test or staging environments that mirror production code paths
- Validate expiration for every certificate in the chain, not only the leaf certificate
- Rely on a synchronized time source (NTP) for the host performing validation, since clock skew can cause incorrect accept or reject decisions
- Treat expiration failures the same as other trust failures - fail closed and refuse the connection or operation
- Monitor certificate expiration proactively (inventory and alerting) as a defence-in-depth measure separate from runtime validation
- Know the named opt-outs, since each disables the date check while leaving the rest of validation looking intact: .NET's `X509VerificationFlags.IgnoreNotTimeValid` (or a `RemoteCertificateValidationCallback` that accepts a chain whose only status is `NotTimeValid` - a shape that appears in Microsoft's own `SslStream` documentation), Java's `PKIXParameters.setDate()` pinned to a past instant, and OpenSSL's `X509_V_FLAG_NO_CHECK_TIME`
- A custom verification callback that returns success on any path it does not explicitly reject has this defect by construction - it never compares the validity dates against the current time at all
- Disabling validation wholesale takes the validity period with it, so a finding here is often the CWE-295 finding seen from a different angle

## Remediation Steps

- Locate - Find certificate validation code paths and any custom logic that reads notBefore/notAfter fields
- Trace data flow - Follow the certificate object from receipt through to the point where validity should be checked
- Identify the unsafe pattern - Disabled validation, caught and swallowed expiration exceptions, custom date logic that omits the check, or client configuration that ignores date errors
- Replace with the safe pattern - Use the platform or library's default certificate validation, which enforces expiration, and remove any suppression of date errors
- Add secondary controls - Add expiration monitoring and alerting for certificates in inventory, and prefer short-lived certificates with automated renewal
- Test - Present an expired certificate and a not-yet-valid certificate and confirm both are rejected; present a currently valid certificate and confirm acceptance
