# CWE-329: Generation of Predictable IV with CBC Mode

## LLM Guidance

CBC mode requires a random, unpredictable Initialization Vector (IV) for each encryption operation. Using static, sequential, or predictable IVs enables plaintext recovery through IV manipulation attacks, completely breaking encryption security even with the correct key.

## Key Principles

- Never reuse IVs when encrypting with CBC mode and the same key
- Always generate IVs using cryptographically secure random number generators
- Generate a fresh, unpredictable IV for each encryption operation
- Store or transmit the IV alongside the ciphertext (IV does not need to be secret)
- Ensure IV size matches the cipher block size (typically 16 bytes for AES)
- A plain counter is not a CBC IV: CBC requires the IV to be *unpredictable* before the plaintext is chosen. NIST SP 800-38A does permit deriving one by encrypting a unique nonce under the same key, but that is a deliberate construction rather than what a counter IV is
- Distinguish the two requirements: CBC needs an unpredictable IV, while GCM and other nonce-based AEAD modes need nonce *uniqueness* - a repeated GCM nonce under the same key is catastrophic, not merely weak
- Use the mode's recommended nonce size (96 bits for GCM) and manage the nonce explicitly unless the library does it, since many APIs make it the caller's responsibility
- The IV is not a secret and belongs with the ciphertext - prepend it - and it must be independent of the data being encrypted

## Remediation Steps

- Locate predictable IV usage - Review flaw details to identify the specific file, line number, and code pattern using CBC mode with static, sequential, or reused IVs
- Identify current IV generation - Determine if IV is hardcoded, derived from a counter/timestamp, or reused across encryptions
- Use cryptographically secure randomness - Replace with `SecureRandom` (Java), `os.urandom()` (Python), or `crypto.randomBytes()` (Node.js)
- Generate fresh IV per encryption - Create a new random IV immediately before each encryption operation
- Store IV with ciphertext - Prepend or append the IV to the encrypted output for use during decryption
- Verify IV uniqueness - Ensure no IV is ever reused with the same encryption key across different messages
