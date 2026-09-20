# CWE-760: Use of a One-Way Hash with a Predictable Salt

## LLM Guidance

A salt is present but predictable, so a table can be precomputed for that one salt value and salting is defeated as effectively as by having none. Where no salt is present at all the finding is CWE-759, and both sit under CWE-916 with the same fix.

## Key Principles

- Salts must come from a cryptographically secure random number generator, generated fresh and independently for every credential - never derived from a deterministic or guessable value
- Never use a username, email, sequential ID, timestamp, or other public/low-entropy field as a salt or as input to derive one
- Never hardcode a single salt value shared across all users - that is functionally equivalent to using no salt at all
- Prefer an adaptive password hashing function (bcrypt, Argon2, scrypt) that generates and manages the salt internally, so a predictable-salt mistake cannot be introduced at the call site
- Store the generated salt alongside the hash; its value does not need to be secret, only unpredictable at generation time
- A salt derived from the account - the username, the user id, the email, the row's creation timestamp - is not a salt: an attacker who has the database has those values too, so the table can be built per target
- One salt shared across all records is equivalent to no salt for precomputation purposes, since a single table still covers every row
- The salt does not need to be secret, only unpredictable and unique per credential; store it alongside the hash, which is what the standard password-hash encodings already do

## Remediation Steps

- Locate - Identify where a password or comparable secret is hashed for storage or verification and how the salt for that hash is produced
- Trace the salt source - Determine whether the salt comes from a CSPRNG or is derived from a predictable value (constant, username, timestamp, sequential counter)
- Identify the unsafe pattern - Confirm the salt is either constant across records or computable by an attacker who knows public information about the account
- Replace with the safe pattern - Switch to an adaptive password hashing function that generates a unique, cryptographically random salt per call, or generate the salt explicitly from a CSPRNG if manual salting is unavoidable
- Plan a migration - Treat existing rows hashed with a predictable salt as compromised and re-hash them with a newly generated random salt, typically on next successful login
- Test - Hash the same secret twice and confirm the resulting salts and hashes differ each time, and that the salt cannot be derived from any public account attribute
