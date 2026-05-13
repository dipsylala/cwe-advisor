# CWE-295: Improper Certificate Validation

## LLM Guidance

Improper certificate validation occurs when an application fails to correctly verify the authenticity of SSL/TLS certificates during secure connections. This undermines the entire purpose of HTTPS by allowing attackers to intercept encrypted communications (man-in-the-middle attacks), impersonate legitimate servers, and steal credentials or sensitive data in transit.

SSL/TLS certificates serve two critical purposes: authentication (prove the server is who it claims to be) and encryption (establish a secure encrypted channel). When certificate validation is disabled or improperly implemented, encryption alone is insufficient - you may be encrypting data to an attacker's server.

## Key Principles

- Never disable TLS certificate validation or hostname verification
- Remove trust-all callbacks and dangerous certificate validators
- Use platform trust stores for public CAs and install private CAs into trusted stores
- For custom validation, validate the full certificate chain and expected hostname
- Fail closed on any certificate, chain, revocation, or name validation error

## Remediation Steps

- Locate certificate validation callbacks, custom trust managers, or flags that ignore TLS errors
- Remove bypasses such as callbacks that always return `true` or hostname verifiers that accept all hosts
- Restore default platform certificate validation wherever possible
- Configure private/internal CAs by adding them to the appropriate trust store instead of bypassing checks
- If custom validation is unavoidable, verify the full chain, hostname, revocation policy, and expected trust anchor
- Test with expired, self-signed, wrong-hostname, and untrusted-chain certificates to confirm failures are blocked
