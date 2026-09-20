# CWE-295: Improper Certificate Validation

## LLM Guidance

Encryption without authentication is the failure mode: with validation disabled the channel is still encrypted - to the attacker's server.

## Key Principles

- Never disable TLS certificate validation or hostname verification
- Remove trust-all callbacks and dangerous certificate validators
- Use platform trust stores for public CAs and install private CAs into trusted stores
- For custom validation, validate the full certificate chain and expected hostname
- Fail closed on any certificate, chain, revocation, or name validation error
- Find out which trust store the *runtime* uses before adding a CA: Java validates against its own `cacerts` keystore and Node against a bundled copy of the Mozilla root list, so an OS-level `update-ca-certificates` may never reach either. Add the CA, then make one request from the runtime itself. This mismatch - works in a browser and in `curl`, fails in the application - is a routine reason verification gets disabled to "make it work"
- Chain validation and hostname verification are separate checks and a client can have one without the other; confirm both, and treat a Common Name-only certificate as a legacy certificate to replace rather than a compatibility target
- Some bypasses are not in application code at all: `NODE_TLS_REJECT_UNAUTHORIZED=0`, `GIT_SSL_NO_VERIFY`, `curl -k` in a wrapper script, a JVM launched with `-Djdk.internal.httpclient.disableHostnameVerification=true`, and a proxy CA injected into the image all disable validation without a line to review. `PYTHONHTTPSVERIFY=0` is a Python 2.7-only relic (PEP 493) that Python 3's `ssl` module never reads - finding it in a Python 3 codebase is dead configuration, not a live bypass

## Remediation Steps

- Locate certificate validation callbacks, custom trust managers, or flags that ignore TLS errors
- Remove bypasses such as callbacks that always return `true` or hostname verifiers that accept all hosts
- Restore default platform certificate validation wherever possible
- Configure private/internal CAs by adding them to the appropriate trust store instead of bypassing checks
- If custom validation is unavoidable, verify the full chain, hostname, revocation policy, and expected trust anchor
- Test with expired, self-signed, wrong-hostname, and untrusted-chain certificates to confirm failures are blocked
