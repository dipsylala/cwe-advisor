# CWE-780: Use of RSA Without OAEP - C# / .NET

## LLM Guidance

In .NET, `RSACryptoServiceProvider` defaults to PKCS#1 v1.5 padding when `fOAEP = false` is passed to `Encrypt()` / `Decrypt()`. PKCS#1 v1.5 is vulnerable to padding oracle and chosen-ciphertext attacks (Bleichenbacher's attack). The fix is to use OAEP padding by passing `fOAEP = true`, or to use the modern `RSA.Create()` API with `RSAEncryptionPadding.OaepSHA256`.

## Key Principles

- Pass `fOAEP: true` to `RSACryptoServiceProvider.Encrypt()` and `Decrypt()`, or switch to `RSA.Create()` with explicit OAEP padding
- Use `RSAEncryptionPadding.OaepSHA256` (or `OaepSHA384`, `OaepSHA512`) — not `OaepSHA1` which uses a deprecated hash
- For data larger than the key size minus OAEP overhead (~190 bytes for 2048-bit), use hybrid encryption: encrypt a random AES-256 key with RSA-OAEP, encrypt data with AES-GCM
- Prefer `RSA.Create()` (CNG-backed) over `RSACryptoServiceProvider` (CAPI) for new code
- Minimum key size: 2048 bits; prefer 4096 bits for long-lived keys

## Remediation Steps

- Find `rsa.Encrypt(data, false)` calls — the `false` argument means PKCS#1 v1.5; change to `true` for OAEP
- Migrate from `RSACryptoServiceProvider` to `RSA.Create()` and call `rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256)`
- Update corresponding `Decrypt()` calls to use the same padding parameter
- For hybrid encryption, generate a fresh `Aes.Create()` key, encrypt the plaintext with AES-GCM, then encrypt the AES key with RSA-OAEP
- Verify imported public/private key material is still compatible after the padding change
- Test roundtrip encryption/decryption after the migration

## Safe Pattern

```csharp
using System.Security.Cryptography;

// SAFE: RSA.Create() with explicit OAEP-SHA256 padding
public static byte[] EncryptWithRsa(byte[] plaintext, RSA publicKey)
{
    return publicKey.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
}

public static byte[] DecryptWithRsa(byte[] ciphertext, RSA privateKey)
{
    return privateKey.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
}

// SAFE: hybrid encryption for large payloads
public static (byte[] EncryptedKey, byte[] Nonce, byte[] Ciphertext, byte[] Tag)
    HybridEncrypt(byte[] plaintext, RSA publicKey)
{
    byte[] aesKey = RandomNumberGenerator.GetBytes(32); // 256-bit AES key
    byte[] nonce  = RandomNumberGenerator.GetBytes(12); // 96-bit GCM nonce
    byte[] ciphertext = new byte[plaintext.Length];
    byte[] tag = new byte[16];

    using var aesGcm = new AesGcm(aesKey, tagSizeInBytes: 16);
    aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

    byte[] encryptedKey = publicKey.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
    return (encryptedKey, nonce, ciphertext, tag);
}
```
