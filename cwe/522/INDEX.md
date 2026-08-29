# CWE-522: Insufficiently Protected Credentials

## LLM Guidance

This vulnerability occurs when credentials (passwords, API keys, tokens) are stored or transmitted without adequate protection, making them susceptible to theft or misuse. The core fix is to ensure credentials are protected in transit, at rest, and during processing, never appearing in logs, URLs, or client-visible data.

## Key Principles

- Never hardcode credentials in source code or configuration files committed to version control
- Protect credentials in transit using TLS/HTTPS and at rest using strong encryption
- Use secure credential storage systems (secrets managers, hardware security modules, encrypted vaults)
- Never expose credentials in logs, error messages, URLs, or client-side code
- Apply least-privilege access, and split rotation by credential type. Machine credentials - API keys, service-account passwords, signing keys - are rotated on a schedule. User passwords are not: NIST SP 800-63B-4 states verifiers "SHALL NOT require subscribers to change passwords periodically" and "SHALL force a change if there is evidence that the authenticator has been compromised", a rule it strengthened from SHOULD NOT in the previous revision. Prescribing 90-day expiry is a finding, not a fix
- Treat environment variables as injection rather than storage: having the platform place a value in the process environment at start-up is legitimate, keeping it in a committed `.env` or a deployment manifest is not. The environment is inherited by every child process, and a container's is readable through `docker inspect`
- Distinguish what needs to be read back from what only needs to be recognised: a password is hashed with an adaptive algorithm and never decrypted, while a credential the application must present to another system is stored in a secrets manager and fetched at runtime
- SHA-256 is not a password hash - it is too fast, which is the property that matters here rather than whether it is broken
- Keep credentials out of the places they leak from by accident: URLs and query strings (server logs, referrer headers, browser history), exception messages, debug logs, and client-visible responses

## Remediation Steps

- Identify all credential locations - review code, configuration files, databases, and transmission points for exposed passwords, API keys, tokens, or private keys
- Remove hardcoded credentials from source code and move to environment variables or secrets management systems (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)
- Implement strong encryption - use bcrypt, Argon2, or PBKDF2 for password hashing; encrypt sensitive data at rest with AES-256
- Secure transmission - enforce HTTPS/TLS for all credential transmission; never send credentials in URL parameters or GET requests
- Implement proper access controls - use multi-factor authentication, enforce least-privilege principles, and rotate credentials on a regular schedule
- Rotate first, then clean up - revoke anything that reached version control before rewriting history, since rotation is what ends the exposure and a rewrite reaches neither existing clones nor forks. `git filter-repo` is what git's own documentation recommends over `filter-branch`
