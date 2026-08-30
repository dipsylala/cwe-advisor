# CWE-780: Use of RSA Algorithm without OAEP - Python

## LLM Guidance

Using RSA encryption without OAEP padding enables padding oracle attacks, chosen ciphertext attacks, and message malleability. This occurs when using deprecated PyCrypto or not specifying OAEP padding with the `cryptography` library. Prefer the modern `cryptography` library with explicit OAEP padding and SHA-256 or stronger hash algorithms; PyCryptodome can also be safe when configured with OAEP and SHA-256.

## Key Principles

- Use `cryptography` library with explicit `padding.OAEP()`; if using PyCryptodome, configure `PKCS1_OAEP` with SHA-256
- Specify MGF1 hash (SHA-256 minimum) and OAEP hash algorithm explicitly
- Use 3072-bit RSA keys for new key generation (NIST SP 800-57 Part 1 disallows 2048-bit/112-bit-strength RSA after 2030, rating 3072-bit at 128-bit strength); 4096-bit for longer-lived keys, 2048 only on an existing key not yet due for rotation
- Never use `PKCS1v15()` or `PKCS1_v1_5` for encryption

## Taint Sinks

`padding.PKCS1v15()` (`cryptography`), `PKCS1_v1_5.new()` (PyCrypto/PyCryptodome)

## Remediation Steps

- Replace deprecated PyCrypto and any `PKCS1_v1_5` encryption; PyCryptodome `PKCS1_OAEP` is acceptable when configured with SHA-256
- Install - `pip install cryptography`
- Use `padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)`
- Verify `rsa.generate_private_key(public_exponent=65537, key_size=...)` uses `key_size=3072` for a new key, not the 2048 floor alone
- Test encryption/decryption with OAEP padding
- Remove deprecated PyCrypto imports; do not remove maintained PyCryptodome solely because it uses the `Crypto` package namespace
