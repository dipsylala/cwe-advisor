# CWE-798: Use of Hard-coded Credentials

## LLM Guidance

Hard-coded credentials occur when authentication secrets (passwords, API keys, encryption keys, tokens) are embedded directly in source code, configuration files, or binaries. This violates the principle of separation of code and configuration - credentials become visible to anyone with code access, changing them requires redeployment, they persist in version control history, and credential rotation becomes nearly impossible.

## Remediation Steps

- Locate hard-coded secrets in source, config, tests, scripts, and committed history
- Remove secrets from code and load them from environment variables, secret managers, or vault-backed configuration
- Rotate and revoke any credential that was committed or exposed
- Scrub repository history or invalidate old versions where exposure cannot be removed safely
- Add secret scanning to CI and pre-commit hooks to prevent reintroduction
- Restrict runtime secret access with least privilege and audit access

## Key Principles

1. Remove hard-coded secrets from source and config.
2. Load secrets from environment variables or a secrets manager.
3. Rotate and revoke exposed credentials.
4. Restrict secret access by least privilege.
