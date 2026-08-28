# CWE-256: Plaintext Storage of a Password

## LLM Guidance

Storing passwords in plaintext (database, files, configuration, logs) exposes all user credentials if storage is compromised. Passwords must be hashed with strong algorithms (bcrypt, Argon2, PBKDF2) using salts, making them computationally infeasible to reverse even if the database is stolen.

## Key Principles

- Use strong, salted, slow hashing algorithms (Argon2, bcrypt, scrypt, or PBKDF2-HMAC-SHA256 where required)
- Never store passwords in reversible form (plaintext, encoding, weak hashing, encryption)
- Implement proper work factors to resist brute-force attacks
- Use unique salts per password to prevent rainbow table attacks
- Never log, cache, or expose passwords in API responses
- Encrypting instead of hashing is not a fix: anyone who also obtains the key recovers every password at once, which is CWE-257 rather than a remediation of this weakness
- A fast general-purpose hash (MD5, SHA-256) stops casual plaintext reading and not a real attack - billions of guesses per second on commodity hardware - which moves the finding to CWE-916 rather than closing it
- Check the transit path as well as the column: a password still written to an access log, error log, or APM trace on the way in is just as recoverable from a different location
- Migrate the data, not only the schema: a new hash column used for new accounts leaves existing rows exactly as exploitable as before, so rehash on next successful login and force a reset for accounts that never return
- Distinguish the neighbours by what the column holds: a reversible encoding is CWE-261 (and needs decode-then-hash migration rather than hash-in-place), a reversible encryption is CWE-257, and a secret embedded in source is CWE-798/CWE-259

## Remediation Steps

- Check database schema - Identify VARCHAR password columns that should contain hashed values
- Review configuration files - Remove passwords from .properties, .env, and config files
- Search codebase for logging - Eliminate password variables from log statements
- Audit client-side storage - Remove passwords from cookies and session storage
- Review API responses - Ensure passwords are never returned in responses
- Replace plaintext storage - Implement bcrypt, Argon2, scrypt, or PBKDF2-HMAC-SHA256 with automatic salt generation and current work factors
- Migrate existing passwords - Hash plaintext passwords on next user login, prompt password reset if needed
