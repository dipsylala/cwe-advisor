# CWE-780: Use of RSA Without OAEP - Python

## LLM Guidance

Using RSA encryption without OAEP padding enables padding oracle attacks, chosen ciphertext attacks, and message malleability. This occurs when using deprecated PyCrypto or not specifying OAEP padding with the `cryptography` library. Prefer the modern `cryptography` library with explicit OAEP padding and SHA-256 or stronger hash algorithms; PyCryptodome can also be safe when configured with OAEP and SHA-256.

## Key Principles

- Use `cryptography` library with explicit `padding.OAEP()`; if using PyCryptodome, configure `PKCS1_OAEP` with SHA-256
- Specify MGF1 hash (SHA-256 minimum) and OAEP hash algorithm explicitly
- Set minimum 2048-bit RSA keys (3072-bit or 4096-bit recommended)
- Never use `PKCS1v15()` or `PKCS1_v1_5` for encryption

## Remediation Steps

- Replace deprecated PyCrypto and any `PKCS1_v1_5` encryption; PyCryptodome `PKCS1_OAEP` is acceptable when configured with SHA-256
- Install - `pip install cryptography`
- Use `padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)`
- Verify key size is at least 2048 bits in `rsa.generate_private_key()`
- Test encryption/decryption with OAEP padding
- Remove deprecated PyCrypto imports; do not remove maintained PyCryptodome solely because it uses the `Crypto` package namespace

## Safe Pattern

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Encrypt with OAEP
ciphertext = public_key.encrypt(
    b"sensitive data",
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(), label=None)
)

# Decrypt
plaintext = private_key.decrypt(ciphertext, padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(), label=None))
```
