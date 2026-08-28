# CWE-798: Use of Hard-coded Credentials

## LLM Guidance

Hard-coded credentials occur when authentication secrets (passwords, API keys, encryption keys, tokens) are embedded directly in source code, configuration files, or binaries. This violates the principle of separation of code and configuration - credentials become visible to anyone with code access, changing them requires redeployment, they persist in version control history, and credential rotation becomes nearly impossible.

## Key Principles

- Load the secret from a secrets manager or the environment at runtime, remove the literal from source and config, and scope the runtime identity to only the secrets it needs
- Establish what the secret currently authenticates before replacing it: a hard-coded signing or encryption key means every token, cookie, or record ever produced with it is forgeable, and rotating it invalidates all of them at once. Say what the rotation breaks - outstanding sessions, stored ciphertext, in-flight webhooks, cached client credentials - and whether a dual-key window is needed to roll it without an outage
- Entropy-based scanning finds the long random-looking strings and misses everything else: a default password, an HMAC key that is a dictionary word, a customer number used as an API key, and a private key split across concatenated lines are all hard-coded credentials no scanner will flag
- Treat environment variables as a fallback, not a risk-free store - they can still leak via process inspection, debug dumps, or cloud metadata endpoints
- Search for comparisons as well as assignments: a hard-coded credential used to *check* an incoming value (`if key == "..."`) is a backdoor, and every `password=`-style pattern finds only the assignment half
- Treat test fixtures as in scope - a mock credential is frequently a real one that was pasted in
- Rotate before removing: deleting the literal changes what the code does and not who holds the secret, since it remains in history, in clones, in CI logs, and in built artifacts

## Remediation Steps

- Locate hard-coded secrets in source, config, tests, scripts, and committed history
- Remove secrets from code and load them from environment variables, secret managers, or vault-backed configuration
- Rotate and revoke any credential that was committed or exposed
- Scrub repository history or invalidate old versions where exposure cannot be removed safely
- Add secret scanning to CI and pre-commit hooks to prevent reintroduction
- Restrict runtime secret access with least privilege and audit access
