# CWE-326: Inadequate Encryption Strength - Go

## LLM Guidance

Go still ships `crypto/des`, `crypto/rc4`, `crypto/md5` and `crypto/sha1`, each carrying a doc comment that the algorithm "is cryptographically broken and should not be used for secure applications" - but none is formally deprecated, so nothing in the toolchain flags them. The other half of this finding is an insecure construction built from sound primitives: AES through a hand-rolled ECB loop, CBC with a static IV, or an RSA key at the smallest size the toolchain still permits. Fix with `cipher.NewGCM` or `chacha20poly1305`, an adequate key size, and modern hashing - checking the Go version each time, because several of these behaviours changed in Go 1.24.

## Key Principles

- Use AES-GCM (`crypto/aes` with `cipher.NewGCM`) or ChaCha20-Poly1305 (`golang.org/x/crypto/chacha20poly1305`). `NewGCM`'s documented "128-bit" is the block size, not the key size - pass a 32-byte key for AES-256. Prefer `chacha20poly1305.NewX` over `New` where nonces are randomly generated: `New`'s 12-byte nonce is documented as "too short to be safely generated at random if the same key is reused more than 2^32 times"
- `crypto/rsa` rejects keys below 1024 bits from Go 1.24, in `GenerateKey` and in every `Sign`, `Verify`, `Encrypt` and `Decrypt` method, with `GODEBUG=rsa1024min=0` as the documented test-only escape. 1024 itself is still accepted, so the enforced floor is below the 2048 you want and a 1024-bit key passes silently. In FIPS 140-only mode the floor becomes a hard 2048
- `crypto/sha3` entered the standard library in Go 1.24; before that the only import path is `golang.org/x/crypto/sha3`, which survives as a thin wrapper plus the legacy Keccak variants
- `tls.Config.MinVersion` already defaults to TLS 1.2 - for clients since Go 1.18 and for servers since Go 1.22. Setting it explicitly is not a change on a current toolchain; its live effect is that it also overrides `GODEBUG=tls10server=1`. Leave `CipherSuites` nil, noting that the field governs TLS 1.0-1.2 only and TLS 1.3 suites are not configurable at all
- `crypto/rand.Read` never returns an error from Go 1.24 - it calls `io.ReadFull` on `Reader` internally and crashes the program irrecoverably instead. Keep the `err` check for older toolchains, but the error branch has nothing useful to do; a fallback to `math/rand` there is itself the finding
- `golang.org/x/crypto/bcrypt` is asymmetric about its 72-byte limit: `GenerateFromPassword` returns `ErrPasswordTooLong` (from x/crypto v0.5.0; earlier versions truncate silently) while `CompareHashAndPassword` has no length check at all and still truncates. `DefaultCost` is 10
- `EncryptPKCS1v15` carries a "WARNING: use of this function to encrypt plaintexts other than session keys is dangerous. Use RSA OAEP in new protocols." PKCS#1 v1.5 *signatures* carry no such warning and remain standard - do not fold the two together

## Taint Sinks

`crypto/des`, `crypto/rc4`, `crypto/md5`, `crypto/sha1`, `rsa.GenerateKey(rand.Reader, 1024)`, `cipher.NewCBCEncrypter`, `rsa.EncryptPKCS1v15`, manual per-block `block.Encrypt` loops

## Remediation Steps

- Read `go.mod` for the language version first: the RSA floor, `crypto/sha3` and the `crypto/rand` guarantee all begin at Go 1.24
- Trace what is protected and for how long, then replace the primitive: swap DES, RC4 and hand-rolled ECB for `cipher.NewGCM(block)` over an AES-256 key, and MD5 or SHA-1 for `sha256.Sum256`. `gcm.Seal(nonce, nonce, plaintext, nil)` prefixes the nonce because `dst` is the nonce slice and `Seal` appends to `dst`, so decryption must split it back as `gcm.Open(nil, out[:gcm.NonceSize()], out[gcm.NonceSize():], nil)` - or use `cipher.NewGCMWithRandomNonce` (Go 1.24), which does the prefixing and extraction itself
- Derive password-based keys with `argon2.IDKey`, supplying RFC 9106's parameters explicitly - time=1, memory=2*1024*1024 KiB, threads=4, or time=3, memory=64*1024 KiB, threads=4 where memory is scarce. `IDKey` returns no error, so a bad parameter is not reported
- For RSA-OAEP, pass the same hash on both sides (`sha256.New()` is the documented reasonable choice) and check the plaintext against OAEP's ceiling of the modulus length minus twice the hash length minus 2. Where the requirement is key agreement rather than key transport, X25519 establishes a shared secret and encrypts nothing, so it replaces RSA's transport role rather than RSA itself
- Read nonces and keys with `crypto/rand`, sizing the buffer from `gcm.NonceSize()` rather than a literal, and never reuse a nonce under one key
- Test with a payload that discriminates. Confirming that identical plaintext blocks yield differing ciphertext catches only the ECB case: RC4, DES-CBC and CBC with a static IV all pass it, because a stream cipher and CBC chaining both diverge within a message. Verify each sink by the construction it uses. Then decrypt through a separately constructed AEAD - a round-trip that keeps the nonce in a local variable passes while the stored ciphertext is undecryptable - and assert `key.N.BitLen()` after generation rather than trusting the argument to `rsa.GenerateKey`
- If the build must run under FIPS 140-3 mode (`GOFIPS140`, or the `fips140` GODEBUG from Go 1.24), note that ChaCha20-Poly1305 is not among the approved algorithms - choose AES-GCM there rather than carrying an option the mode will refuse
