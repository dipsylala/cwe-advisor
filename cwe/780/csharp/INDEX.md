# CWE-780: Use of RSA Algorithm without OAEP - C#

## LLM Guidance

In .NET, `RSACryptoServiceProvider` defaults to PKCS#1 v1.5 padding when `fOAEP = false` is passed to `Encrypt()` / `Decrypt()`. PKCS#1 v1.5 is vulnerable to padding oracle and chosen-ciphertext attacks (Bleichenbacher's attack). Passing `fOAEP = true` is a legacy minimum improvement but is fixed to OAEP-SHA1 - `RSACryptoServiceProvider` cannot be parameterized to a stronger OAEP hash even via its `RSAEncryptionPadding` overload, which itself needs .NET Framework 4.6+. The `Encrypt(byte[], bool)`/`Decrypt(byte[], bool)` overloads are obsolete from .NET 11 (SYSLIB0064). New code should use `RSA.Create()` with `RSAEncryptionPadding.OaepSHA256`.

## Key Principles

- Prefer `RSA.Create()` with explicit OAEP-SHA256 padding; use `fOAEP: true` only as a legacy minimum improvement
- Use `RSAEncryptionPadding.OaepSHA256` (or `OaepSHA384`, `OaepSHA512`) - not `OaepSHA1` which uses a deprecated hash
- For data larger than the key size minus OAEP overhead (~190 bytes for 2048-bit), use hybrid encryption: encrypt a random AES-256 key with RSA-OAEP, encrypt data with AES-GCM
- Prefer `RSA.Create()` (CNG-backed) over `RSACryptoServiceProvider` (CAPI) for new code
- Use 3072-bit keys for new key generation (NIST SP 800-57 Part 1 disallows 2048-bit/112-bit-strength RSA after 2030); 4096 bits for long-lived keys, 2048 only on an existing key not yet due for rotation
- Use `RSAEncryptionPadding.OaepSHA256` explicitly rather than the PKCS#1 v1.5 overload, and catch `CryptographicException` into one generic failure - a distinguishable decode error is the oracle the attack needs
- `ImportParameters` with a public-only key still encrypts; make sure the private key material is loaded from the store rather than embedded (CWE-321)

## Taint Sinks

`RSACryptoServiceProvider.Encrypt(data, false)`, `RSA.Encrypt()`/`Decrypt()` with `RSAEncryptionPadding.Pkcs1`

## Remediation Steps

- Find `rsa.Encrypt(data, false)` calls - the `false` argument means PKCS#1 v1.5; migrate to `RSA.Create()` with OAEP-SHA256 where possible
- Migrate from `RSACryptoServiceProvider` to `RSA.Create()` and call `rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256)`
- Update corresponding `Decrypt()` calls to use the same padding parameter
- For hybrid encryption, generate a 32-byte key and 12-byte nonce with `RandomNumberGenerator.GetBytes()`, encrypt the plaintext with `new AesGcm(key, tagSizeInBytes: 16)`, then encrypt the AES key with RSA-OAEP
- Verify imported public/private key material is still compatible after the padding change
- Test roundtrip encryption/decryption after the migration
