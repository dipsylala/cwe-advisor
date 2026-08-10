# CWE-759: Use of a One-Way Hash without a Salt

## LLM Guidance

Hashing a password or comparable secret without a salt means identical inputs always produce identical hashes, so an attacker who obtains the hash store can crack every account sharing a password with a single precomputed lookup. The fix is to use a purpose-built, adaptive password hashing algorithm that generates and manages a unique random salt automatically, so salting cannot be skipped at a call site. Migrating existing unsalted hashes requires a controlled re-hash strategy, since the old and new formats cannot be compared directly.

## Key Principles

- Use an adaptive, purpose-built password hashing function, not a general-purpose or fast cryptographic hash, as the primary defence
- Rely on the hashing function's built-in salt generation and storage rather than managing salts by hand
- If a salt must be generated manually, source it from a cryptographically secure random generator, make it unique per credential, and store it alongside the hash
- Never reuse a salt across users or derive it from a predictable value such as a username or timestamp
- Keep the hashing work factor configurable so it can be increased as hardware improves
- Treat unsalted or predictably salted stores as compromised data at rest and plan a migration rather than leaving them in place

## Remediation Steps

- Locate - Identify every place a password or comparable secret is hashed for storage or verification
- Trace data flow - Follow the secret from where it is submitted to the hash function call and the storage of the resulting value
- Identify the unsafe pattern - Look for a hash function called with only the secret as input, with no salt parameter, or with a constant or predictable salt
- Replace with the safe pattern - Switch to an adaptive password hashing function that generates a unique random salt per call and stores the salt with the hash
- Add secondary controls - Track which stored records still use the old unsalted format and re-hash them with the new function on next successful login rather than forcing an immediate mass invalidation
- Test - Hash the same secret for two different accounts and confirm the stored values differ; confirm each stored record carries its own salt
