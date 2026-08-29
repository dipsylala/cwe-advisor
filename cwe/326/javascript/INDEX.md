# CWE-326: Inadequate Encryption Strength - JavaScript

## LLM Guidance

Weak cryptography in Node.js comes from the `crypto` module offering the broken options alongside the sound ones, and from key derivation left on parameters that were adequate a decade ago. Two things decide whether a given finding is even reachable: the Node version, since several of these APIs were removed or gained defaults recently, and the OpenSSL provider, since some legacy ciphers no longer load at all. Fix with AES-256-GCM or ChaCha20-Poly1305, and a password KDF whose parameters are stated rather than implied.

## Key Principles

- `crypto.pbkdf2()` takes `digest` as a required positional argument - `crypto.pbkdf2(password, salt, iterations, keylen, digest, callback)`. Omitting it was deprecated in Node 6 because it defaulted to SHA-1, and passing `undefined` has thrown a `TypeError` since Node 8 (`null` since Node 14). A prescribed `crypto.pbkdf2()` call with no digest does not run
- OWASP's iteration counts are per HMAC: 600,000 for PBKDF2-HMAC-SHA256, 220,000 for SHA-512, 1,400,000 for SHA-1 which it marks legacy-only. OWASP orders its recommendations Argon2id, then scrypt, then bcrypt for legacy systems, with PBKDF2 as the branch for FIPS-140 compliance rather than a general first choice
- Argon2 is in Node core from v24.7.0 as `crypto.argon2` / `crypto.argon2Sync`, taking `message`, `nonce` (at least 8 bytes), `parallelism`, `tagLength`, `memory` in 1 KiB blocks and `passes`; Node's WebCrypto gained Argon2 in v24.8.0 behind OpenSSL 3.2. Below that floor use the maintained packages `argon2` or `@node-rs/argon2`
- `crypto.scrypt` defaults to `cost` 16384 (2^14), `blockSize` 8, `parallelization` 1 and `maxmem` 32 MiB, and errors when `128 * N * r > maxmem`. OWASP's recommended N=2^17 needs 128 MiB, so raising `cost` to OWASP's figure without also raising `maxmem` fails rather than strengthening anything
- `crypto.timingSafeEqual()` compares *byte* length, not character count, and throws `ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH` when the lengths differ - hash both sides first where they can. Node's own note is that it "does not guarantee that the surrounding code is timing-safe"
- The two bcrypt packages behave differently and the entry must name which one. `bcrypt`'s own README states its comparison "is _not_ time safe (constant-time), as it may exit early when a mismatch is found", arguing that this is acceptable because it compares hash digests; `bcryptjs` routes both `compare` and `compareSync` through a constant-time `safeStringCompare`. On the 72-byte limit, `bcrypt` silently ignores the excess bytes while `bcryptjs` does not check but ships `bcrypt.truncates(password)` to test for it

## Taint Sinks

`crypto.createCipher(`, `crypto.createCipheriv('des-cbc'`, `crypto.createCipheriv('des-ede3-cbc'`, `crypto.createCipheriv('rc4'`, `crypto.createCipheriv('aes-128-ecb'`, `crypto.createHash('md5')`, `crypto.createHash('sha1')`, `crypto.pbkdf2(` with a `'sha1'` digest

## Remediation Steps

- Check the Node version and the provider before treating a sink as live. `crypto.createCipher` (no IV) reached end-of-life in Node 22 and is gone, with `npx codemod @nodejs/crypto-createcipheriv-migration` as the migration. Under OpenSSL 3, single-DES and RC4 moved to the legacy provider and need `--openssl-legacy-provider` to load at all, while 3DES (`des-ede3-cbc`), MD5, SHA-1 and `aes-128-ecb` remain in the default provider and still run
- Replace the cipher with `aes-256-gcm` or `chacha20-poly1305` over a 32-byte key from `crypto.randomBytes(32)` and a fresh 12-byte IV per message. Note that a 32-byte key is rejected with `ERR_CRYPTO_INVALID_KEYLEN` by any `aes-128-*` algorithm, so the key size and the algorithm name have to change together
- Do not treat GCM and CCM as interchangeable. GCM's `authTagLength` is optional and defaults to 16; CCM requires it at `createCipheriv`, restricts the nonce to 7-13 bytes, and requires `plaintextLength` on `setAAD`. For `chacha20-poly1305`, `authTagLength` was required before Node 17.9.0/16.17.0 and defaults to 16 after
- Store the salt, IV, ciphertext and `cipher.getAuthTag()` value together, and complete the loop on the decrypt side: the tag only does anything once it is passed to `decipher.setAuthTag()` before `decipher.final()`, which throws `ERR_CRYPTO_INVALID_AUTH_TAG` on a mismatch. Storing it without verifying it is the common half-fix
- Verify through a separately created decipher object rather than the encrypting one. `getAuthTag()` is readable only after `final()`, so a test that reuses the cipher instance passes while the persisted ciphertext can never be authenticated. Flip a byte of the ciphertext, of the tag and of the IV in turn and confirm `decipher.final()` throws `Unsupported state or unable to authenticate data` each time
- Move password hashing to Argon2id, or to scrypt with `maxmem` raised to match the chosen `cost`. Where PBKDF2 must stay for compliance, name `'sha256'` as the digest and set 600,000 iterations - raising the count while leaving the digest at SHA-1 applies the wrong figure to the wrong algorithm
- For browser code, `SubtleCrypto` is available only in a secure context and offers AES-GCM, AES-CBC, AES-CTR, RSA-OAEP, HKDF and PBKDF2 - it has no bcrypt, scrypt or Argon2, so a password hashed client-side cannot use the recommended algorithms and belongs on the server
