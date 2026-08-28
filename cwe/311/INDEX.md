# CWE-311: Missing Encryption of Sensitive Data

## LLM Guidance

Missing Encryption occurs when sensitive data is transmitted or stored without proper cryptographic protection, exposing it to unauthorized access or interception. The core fix is to encrypt sensitive data in transit using TLS 1.2+ and at rest when storage systems are untrusted or exposure is plausible.

## Key Principles

- Treat storage as untrusted-encrypt sensitive data at rest when exposure is plausible
- Use TLS 1.2+ for all network communications transmitting sensitive data
- Never transmit credentials, PII, or secrets over unencrypted channels
- Apply defence-in-depth: combine encryption with access controls and secure key management
- Stored passwords are not an encryption problem, and this is the most common misreading of a "missing encryption" finding: encryption is reversible by design, so a key compromise returns every password in cleartext. Use an adaptive password hash with a per-password salt - Argon2id or scrypt, or bcrypt where neither is available - and see CWE-256, CWE-261 and CWE-916 for the storage variants
- The test for which control applies is whether anything legitimately needs the *original* value back: if not, hash it
- Separate the two cases when remediating: data at rest is CWE-312's ground and data in transit is CWE-319's

## Remediation Steps

- Identify unencrypted sensitive data by reviewing flaw details (file, line, data type - passwords, PII, tokens, API keys)
- Trace data flow to determine if exposure is in transit (network) or at rest (storage, database, files)
- Enforce TLS 1.2+ for all network communications - HTTPS for web traffic, TLS for database connections, secure WebSocket (wss://)
- Encrypt sensitive data at rest using AES-256 or equivalent when stored in databases, files, or untrusted systems
- Implement secure key management - use hardware security modules, key vaults, or secrets management services-never hardcode keys
- Validate encryption coverage - verify no plaintext sensitive data exists in logs, backups, or temporary files
