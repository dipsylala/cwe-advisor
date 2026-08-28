# CWE-615: Inclusion of Sensitive Information in Source Code Comments

## LLM Guidance

Sensitive information in source code comments (passwords, API keys, internal IPs, security TODOs) is exposed to anyone with code access through version control, decompiled binaries, or client-side JavaScript. This data persists in git history even after removal, creating long-term security risks.

## Key Principles

- Never include credentials, API keys, or authentication data in comments
- Avoid exposing internal architecture details (IPs, server names, internal URLs) in comments
- Remove security-related TODOs or vulnerability discussions before committing code
- Ensure client-visible code contains no development artifacts or internal information
- Treat code comments as publicly accessible content
- Delete rather than disable: commented-out code holding a real credential must be removed, since "temporary" comments become permanent and commenting a check out is not the same as removing the secret
- Fix a security TODO before deleting it - a comment describing an unfixed weakness is a roadmap, and removing the comment without the fix only hides it
- Rotate anything that was ever committed: deleting the line changes the working tree and not who has the secret, since it remains in history, in clones, and in built artifacts
- Documentation that must exist belongs in a docs repository rather than inline in code that ships to clients

## Remediation Steps

- Search for credentials - Scan comments for passwords, API keys, database credentials, and tokens
- Identify internal information - Locate IP addresses, server names, internal URLs, and infrastructure details
- Find security TODOs - Remove comments revealing vulnerabilities or security weaknesses
- Check PII exposure - Look for SSNs, credit card numbers, or personal data in test comments
- Review commented-out code - Remove old code containing passwords or sensitive data
- Sanitize git history - Use tools like `git filter-branch` or BFG Repo-Cleaner to purge sensitive data from repository history
