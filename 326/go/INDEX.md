# CWE-326: Inadequate Encryption Strength - Go

## LLM Guidance

Go's standard library still ships legacy packages (`crypto/des`, `crypto/md5`, `crypto/rc4`, `crypto/sha1`) for backward compatibility, and it is easy to build an insecure construction - AES run through a hand-rolled ECB loop, CBC with a static IV, or an RSA key of 1024 bits - even while using modern primitives elsewhere. The fix is authenticated encryption via `cipher.NewGCM` or `golang.org/x/crypto/chacha20poly1305`, adequate key sizes, modern hashing, and `crypto/tls.Config.MinVersion` for transport.

## Key Principles

- Use AES-256-GCM (`crypto/aes` + `cipher.NewGCM`) or ChaCha20-Poly1305 (`golang.org/x/crypto/chacha20poly1305`) for symmetric encryption; both provide authentication, preventing undetected tampering
- Never use `crypto/des`, `crypto/rc4`, or a manual ECB loop (`block.Encrypt` per block without chaining); avoid plain CBC without a MAC
- Use `crypto/sha256` or `crypto/sha3` for hashing; avoid `crypto/md5` and `crypto/sha1` for anything security-relevant
- Derive keys from passwords with `golang.org/x/crypto/argon2` (Argon2id) or `golang.org/x/crypto/bcrypt`; never a bare `md5.Sum` or `sha256.Sum256` of the password
- Generate RSA keys with `rsa.GenerateKey(rand.Reader, 2048)` at minimum (4096 for long-lived secrets); use `rsa.EncryptOAEP`, not PKCS#1 v1.5 padding, for new code
- For TLS, set `tls.Config.MinVersion: tls.VersionTLS12` or higher; leave `CipherSuites` unset to use Go's maintained safe defaults rather than hand-picking ciphers

## Remediation Steps

- Locate - search for `crypto/des`, `crypto/rc4`, `crypto/md5`, `crypto/sha1`, `rsa.GenerateKey(rand.Reader, 1024`, and manual per-block `Encrypt` loops
- Trace data flow - identify what is encrypted or hashed (data at rest, tokens, passwords) and whether the value is persisted or transmitted long-term
- Replace the unsafe pattern - swap DES/RC4/ECB for `cipher.NewGCM(block)` with an AES-256 key, or swap MD5/SHA-1 for `sha256.Sum256`
- Generate keys and nonces securely - use `crypto/rand.Reader` with `io.ReadFull` for all keys, nonces, and salts; never derive them with `math/rand`
- Harden configuration - centralize the algorithm/key-size choice in one helper so call sites cannot select a weaker cipher, and set `MinVersion: tls.VersionTLS12` on any `tls.Config`
- Test - verify ciphertext differs for identical plaintext blocks (no ECB pattern leakage), verify `gcm.Open` rejects tampered ciphertext, and confirm key and RSA key sizes meet the minimums in code review or a static check

## Safe Pattern

```go
// SAFE: AES-256-GCM authenticated encryption
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
)

key := make([]byte, 32) // AES-256
io.ReadFull(rand.Reader, key)

block, _ := aes.NewCipher(key)
gcm, _ := cipher.NewGCM(block)

nonce := make([]byte, gcm.NonceSize())
io.ReadFull(rand.Reader, nonce)

// Store as nonce || ciphertext || tag
ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
```
