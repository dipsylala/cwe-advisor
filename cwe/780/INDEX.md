# CWE-780: Use of RSA Algorithm without OAEP

## LLM Guidance

Using RSA encryption without OAEP (Optimal Asymmetric Encryption Padding) enables padding oracle attacks, chosen ciphertext attacks, and message malleability. OAEP adds randomness and integrity checks, making RSA encryption secure against modern attacks. Always use RSA-OAEP instead of raw RSA or PKCS#1 v1.5 padding.

## Key Principles

- Always specify OAEP padding when using RSA encryption with SHA-256 or better (not SHA-1) and MGF1 mask generation function
- Use hybrid encryption for large data: generate random AES-256 key, encrypt data with AES-GCM/ChaCha20-Poly1305, encrypt symmetric key with RSA-OAEP
- Never use "default" RSA without explicitly specifying OAEP padding mode
- Use 3072-bit RSA keys for new keys, not 2048-bit: NIST SP 800-57 Part 1 rates 2048-bit at 112-bit security strength, which its own transition schedule stops permitting after 2030, while 3072-bit reaches 128-bit and stays valid beyond that date. Only treat 2048-bit as acceptable on an existing key you are not yet rotating
- Nothing in testing distinguishes this from the secure version: the encryption round-trips perfectly, and the weakness is in what the *decrypting* side gives away - Bleichenbacher's attack needs only a way to tell "the padding parsed" from "it did not", which an error message, a status code, a log line, or a response-time difference all supply
- Raw textbook RSA is deterministic, so an attacker with the public key encrypts each candidate value and compares - for a PIN, an account number, or a yes/no answer that recovers the plaintext with no attack on RSA at all
- Use hybrid encryption: RSA-OAEP wraps a short symmetric key and the symmetric algorithm carries the data, so the payload is not constrained by RSA's block size

## Remediation Steps

- Locate RSA encryption calls in codebase and identify padding mode used
- Update cipher configuration to explicitly specify OAEP padding with SHA-256 (or better) and MGF1 (see the language-specific guidance's Remediation Steps for the exact cipher/transform string)
- Verify hash algorithms use SHA-256 or better for OAEP and MGF1
- Implement hybrid encryption for data larger than key size minus padding overhead
- Test encryption/decryption end-to-end to ensure compatibility
- Scan for other RSA usage patterns that may need similar fixes
