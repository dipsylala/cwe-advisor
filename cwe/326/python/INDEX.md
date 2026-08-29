# CWE-326: Inadequate Encryption Strength - Python

## LLM Guidance

In Python this appears as a legacy cipher from the `Crypto.*` namespace, an unauthenticated mode, a plain digest standing in for password hashing, or an RSA key below the current floor. `cryptography` is the maintained library, but its layout matters to the fix: `Fernet` is a recipe with the choices already made, while `AESGCM`, `ChaCha20Poly1305`, `rsa`, `ec`, `ed25519` and `x25519` all live under `cryptography.hazmat`, whose own documentation warns they require knowing what you are doing. Match the primitive to the operation - the recurring error here is reaching for a signing algorithm to do encryption.

## Key Principles

- `AESGCM` and `ChaCha20Poly1305` in `cryptography.hazmat.primitives.ciphers.aead` are the authenticated ciphers. `ChaCha20Poly1305` raises `cryptography.exceptions.UnsupportedAlgorithm` at construction when the linked OpenSSL lacks it, so it needs a guard or an AES-GCM fallback rather than an unconditional recommendation
- `Fernet` is AES-128 in CBC mode with HMAC-SHA256, not AES-256: `Fernet.generate_key()` returns 32 bytes that split into a 16-byte signing key and a 16-byte encryption key. It is a sound construction and a 128-bit cipher, so do not cite it as evidence of 256-bit strength, and note it accepts no caller-supplied nonce
- Ed25519 signs and verifies only - it has no `encrypt` and no `exchange`. For key agreement use `x25519` or `ec` with `ECDH`, and keep them separate keys: the library documents that using one elliptic-curve key for both signing and exchange is bad practice
- `rsa.generate_private_key` takes `public_exponent` as a required first argument (65537). Since `cryptography` 43.0.0, released July 2024, it raises `ValueError("key_size must be at least 1024-bits.")`, so sub-1024 keys can no longer be produced there and the live finding is the 1024-to-2047 range
- `cryptography` 43.0.0 moved `TripleDES` and `ARC4` into `cryptography.hazmat.decrepit.ciphers.algorithms`, deprecated them where they were, and announced removal from the `ciphers` module in 48.0.0
- `hashlib` constructors take a keyword-only `usedforsecurity` argument from Python 3.9, defaulting to `True`. CPython documents `False` as declaring a non-security use such as a one-way compression function, so `hashlib.md5(data, usedforsecurity=False)` is a sanctioned call and not this finding
- `os.urandom()` blocks on Linux until the kernel's pool is first initialized (PEP 524) and raises `NotImplementedError` where `/dev/urandom` is unreadable; CPython points to `secrets` as the higher-level interface rather than treating the two as equivalent

## Taint Sinks

`Crypto.Cipher.DES`, `Crypto.Cipher.DES3`, `Crypto.Cipher.ARC4`, `Cryptodome.Cipher.DES`, `hashlib.md5(`, `hashlib.sha1(`, `rsa.generate_private_key(`, `decrepit.ciphers.algorithms.TripleDES`, `algorithms.ARC4`, `modes.ECB(`

## Remediation Steps

- Establish which library is installed before trusting an import path. PyCrypto and PyCryptodome both install under `Crypto`, and pycryptodomex installs the same modules under `Cryptodome`, so the import alone does not identify the package. PyCrypto's last release is 2.6.1 from June 2014 and carries CVE-2013-7459 with no fixed version, making its finding "replace the dependency" rather than "raise a parameter"; PyCryptodome is maintained and acceptable with modern algorithms. The two conflict if installed together
- Replace unauthenticated symmetric encryption with `AESGCM`, keyed from `AESGCM.generate_key(bit_length=256)` or `os.urandom(32)`, using a fresh `os.urandom(12)` nonce on every `encrypt()` call - reusing a nonce under one key destroys both confidentiality and authentication for every message under that key
- Replace DES, 3DES and RC4 knowing that nothing will fail for you: PyCryptodome documents both `Crypto.Cipher.DES` and `Crypto.Cipher.ARC4` as "provided only for legacy purposes" but keeps them working, and `cryptography`'s versions only move module, they do not stop functioning until 48.0.0
- Check RSA sizes against 2048 as the floor and 3072 for anything long-lived, passing `public_exponent=65537` explicitly. Where the finding is asymmetric *encryption* rather than signing, confirm the code is using OAEP padding and not PKCS#1 v1.5
- Replace a password digest rather than strengthening it - `hashlib.sha256` of a password is the wrong primitive whatever salt is applied. Move to `argon2-cffi` or `bcrypt`, and note that Python's `bcrypt` raises on inputs over 72 bytes from version 5.0 where earlier releases truncated silently, so the migration needs an explicit length decision
- Do not route the replacement through `passlib`. Its last release was 1.7.4 in October 2020 and its bcrypt backend reads `bcrypt.__about__`, removed in bcrypt 4.1.0 - a logged warning on bcrypt 4.x and an outright failure on 5.0.0. Use `pwdlib` with Argon2, which is what FastAPI's own security tutorial now recommends, and keep `passlib` only for reading legacy hash formats during the migration
- Verify with a separately constructed decryptor and confirm a flipped byte in the ciphertext, the tag or the nonce raises `InvalidTag` rather than returning plaintext - an AEAD that decrypts modified input is not authenticating it
- Triage each `hashlib.md5`/`sha1` hit for a non-security use and mark it `usedforsecurity=False` instead of replacing it, so what remains after the sweep is the set of real findings
