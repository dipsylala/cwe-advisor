# CWE-522: Insufficiently Protected Credentials - Python

## LLM Guidance

Insufficiently Protected Credentials in Python occurs when passwords, API keys, tokens, or secrets are stored in plaintext, hardcoded in source code, weakly encrypted, or transmitted insecurely. Use secure storage (environment variables, secret managers), strong hashing (bcrypt, Argon2) for passwords, and encrypted channels for transmission.

## Key Principles

- Hash passwords with bcrypt or Argon2, never store plaintext or use weak algorithms like MD5/SHA1
- Store secrets in environment variables or dedicated secret managers (AWS Secrets Manager, HashiCorp Vault)
- Encrypt credentials at rest using cryptography.fernet or equivalent AES encryption
- Transmit credentials only over TLS/HTTPS, never in URL parameters or unencrypted channels
- Rotate credentials regularly and revoke compromised secrets immediately
- Use `passlib`'s `CryptContext` (or `argon2-cffi`/`bcrypt` directly) so the algorithm and its parameters are configuration rather than call sites, and rehash on verify when the configured cost changes
- A `.env` file is a deployment mechanism, not a store: keep it out of the image and out of version control, and prefer a secret fetched at start

## Taint Sinks

hardcoded secrets in source, `hashlib.md5()`/`hashlib.sha1()` for passwords, `print()`/`logging` of credentials

## Remediation Steps

- Replace hardcoded credentials with environment variables loaded via `os.getenv()` or `python-dotenv`
- Install bcrypt (`pip install bcrypt`) and hash passwords before storage with `bcrypt.hashpw(password.encode(), bcrypt.gensalt())`; verify with `bcrypt.checkpw()`
- Configure secret rotation policies and use managed services for production
- Remove credentials from source code, logs, and version control history
- Implement credential scanning in CI/CD pipelines to prevent commits of secrets
- Use credential vaults with IAM-based access controls for team environments
