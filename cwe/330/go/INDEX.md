# CWE-330: Use of Insufficiently Random Values - Go

## LLM Guidance

Go exposes two distinct random-number APIs: `math/rand` (and `math/rand/v2`), a fast non-cryptographic PRNG intended for simulations and test data, and `crypto/rand`, a CSPRNG backed by the OS entropy source. Insufficient randomness in Go usually means a security-relevant value - session token, password reset code, API key, nonce - was generated with `math/rand`, a predictable seed, or too few bytes of entropy. The fix is `crypto/rand.Reader` for every security-sensitive value, sized to resist brute force.

## Key Principles

- Use `crypto/rand.Reader` with `io.ReadFull` (or `rand.Read`) for all tokens, keys, nonces, salts, and reset codes - never `math/rand` or `math/rand/v2`
- Generate at least 16 bytes (128 bits) for tokens and 32 bytes (256 bits) for encryption keys; encode with `encoding/base64.URLEncoding` or `encoding/hex`
- Never seed a non-cryptographic generator with a crypto-random value and keep drawing from it - `math/rand` fed a random seed is still a deterministic algorithm once the seed is fixed
- Avoid predictable inputs mixed into token construction, such as concatenating a user ID or timestamp instead of relying solely on the random bytes
- For random integers in a bounded range (OTPs, random selection), use `crypto/rand.Int(rand.Reader, big.NewInt(n))`, which performs rejection sampling and avoids modulo bias
- `math/rand`/`math/rand/v2` remain acceptable for tests, simulations, and non-security shuffling - keep those usages clearly separated from security code paths
- `math/rand` is not a CSPRNG whatever it is seeded with: `rand.New(rand.NewSource(x))` produces a reproducible stream, and `math/rand/v2` is a newer API for the same non-cryptographic generator
- `crypto/rand` is the security source, and its `Read` returns an error that must be checked - Go 1.24 makes it panic rather than fail silently, but earlier versions do not

## Taint Sinks

`math/rand.Intn()`, `math/rand.Int63()`, `math/rand.Seed()`, `math/rand/v2` used for tokens/keys/nonces

## Remediation Steps

- Locate - search for `math/rand`, `rand.Seed`, `rand.Intn`, and `rand.Int63` near token, key, password-reset, or session generation code
- Trace data flow - confirm the generated value is used for authentication, authorization, or as a cryptographic input, not test data or simulation
- Replace the unsafe pattern - swap `math/rand` calls for `crypto/rand.Reader` reads into a byte slice, or `crypto/rand.Int` for bounded integers
- Size the output - use 16+ bytes for tokens and 32 bytes for keys, and encode with base64 or hex before storage or transmission
- Harden configuration - centralize token and key generation in one reviewed helper so new code cannot accidentally import `math/rand` for a security path
- Test - verify generated values are non-sequential across repeated calls and that production security paths never depend on a fixed seed
