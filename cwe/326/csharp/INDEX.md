# CWE-326: Inadequate Encryption Strength - C#

## LLM Guidance

Inadequate Encryption Strength in .NET appears as a legacy algorithm (`DES`, `TripleDES`, `RC2`, `MD5`, `SHA1`), an unauthenticated cipher mode, or a key-derivation call left on defaults set two decades ago. None of those factories are obsolete or throw on current .NET, so the finding is about what the code selects, not what the runtime allows. Fix by moving to AES-GCM or ChaCha20-Poly1305 for encryption, SHA-256/SHA-512 for digests, and `Rfc2898DeriveBytes.Pbkdf2` with an explicitly named hash algorithm for password-based keys - checking the target framework each time, because several of these APIs arrived later than the .NET 6 the surrounding code may assume.

## Key Principles

- Use authenticated encryption - `AesGcm` or `ChaCha20Poly1305` detect tampering rather than decrypting it silently
- `AesGcm`'s tag-size constructor `AesGcm(key, tagSizeInBytes)` is .NET 8+, and the tag-less constructors are obsolete under `SYSLIB0053` from that release. `AesGcm.TagByteSizes` accepts 12-16 bytes; `AesGcm.NonceByteSizes` accepts only 12, so a nonce sized from `NonceByteSizes.MaxSize` is taking the one legal value rather than the largest of several
- `ChaCha20Poly1305` is .NET 6+ and is not present everywhere - Windows 10 build 20142+, OpenSSL 1.1.0+ on Linux, Android API level 28+, never in the browser, and on iOS/tvOS only from .NET 9. Gate it on the static `IsSupported`, which is what that property is for
- Derive password-based keys with the static `Rfc2898DeriveBytes.Pbkdf2` (.NET 6+). Every `Rfc2898DeriveBytes` constructor defaults to `HashAlgorithmName.SHA1` and 1000 iterations; the defaulting overloads are obsolete under `SYSLIB0041` from .NET 7 and all of them under `SYSLIB0060` from .NET 10
- OWASP's iteration counts are stated per HMAC, not per algorithm - 600,000 for PBKDF2-HMAC-SHA256, 220,000 for SHA-512, and 1,400,000 for SHA-1, which it marks legacy-only
- Generate keys and nonces with the static `RandomNumberGenerator.GetBytes(int)` or `RandomNumberGenerator.Fill(Span<byte>)`, the form Microsoft names as preferred; never `new Random()` or a literal
- Separate keys per purpose - an encryption key must not also sign or MAC

## Taint Sinks

`DES.Create()`, `TripleDES.Create()`, `RC2.Create()`, `MD5.Create()`, `SHA1.Create()`, `HMACSHA1`, `new Rfc2898DeriveBytes(`, `RSA.Create(1024)`, `new RSACng(1024)`, `new RSACryptoServiceProvider(1024)`, `CipherMode.ECB`

## Remediation Steps

- Locate the weak selection, and widen the search past the literal names: a bare `RSA.Create()` with a later `rsa.KeySize = 1024`, or a `new RSACryptoServiceProvider()` left on its 1024-bit default, matches no grep for `RSA.Create(1024)`. .NET enforces no 2048-bit floor - the documented minimums are 384 bits under CNG and 512 on Linux - so nothing rejects a weak key on your behalf
- Replace symmetric encryption with `AesGcm` over a 32-byte key, persisting nonce, ciphertext and tag together, with a fresh `RandomNumberGenerator.GetBytes(12)` nonce per message - repeating a nonce under one key leaks the XOR of the two plaintexts and exposes the authentication subkey, breaking integrity for every message under that key. Note what the code is starting from: `Aes.Create()` defaults to `CipherMode.CBC` and `PaddingMode.PKCS7`, so an instance that never assigned `Mode` is unauthenticated CBC rather than ECB, and the finding is the missing integrity check
- Upgrade digests to `SHA256` or `SHA512`, preferring the one-shot statics such as `SHA256.HashData` (.NET 5+), which are thread-safe and allocation-light where a `Create()` instance is neither
- Replace each `Rfc2898DeriveBytes` constructor call with `Rfc2898DeriveBytes.Pbkdf2` naming `HashAlgorithmName.SHA256` explicitly. Raising the iteration count while leaving the constructor in place keeps the derivation on HMAC-SHA1 and applies 600,000 to the algorithm OWASP rates at 1,400,000 - a change that reads as a fix and lands short of one
- Where CBC has to stay, apply Microsoft's encrypt-then-MAC guidance in full: MAC the IV as well as the ciphertext, derive separate cipher and MAC keys from the master key, verify the MAC before decrypting anything, and compare with `CryptographicOperations.FixedTimeEquals`. An HMAC over the ciphertext alone, or one checked after decryption, leaves the padding-oracle vector open
- Move keys to a managed store, and check the deployment target before naming one. `ProtectedData`/DPAPI is Windows-only: it needs the `System.Security.Cryptography.ProtectedData` package and throws `PlatformNotSupportedException` on Linux and macOS, so a cross-platform service needs Azure Key Vault or an equivalent instead
- Confirm the check actually runs before treating a clean build as evidence - `CA5351` flags `MD5.Create()`, `DES.Create()` and `RC2.Create()`, but it is not enabled by default
