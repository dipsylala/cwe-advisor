# CWE-330: Use of Insufficiently Random Values - Go

## LLM Guidance

Go separates `math/rand` (and `math/rand/v2`), non-cryptographic generators for simulation and test data, from `crypto/rand`, a CSPRNG backed by the OS. A CWE-330 finding here means a token, reset code, API key or nonce came from the former. What has changed is how the finding presents: since Go 1.20 the global `math/rand` source is randomly seeded, since 1.22 it is ChaCha8-backed, and since 1.24 the top-level `Seed` call does nothing at all. Read `go.mod` before triaging, because the same source file means different things across those releases.

## Key Principles

- Draw every security-relevant value from `crypto/rand`. From Go 1.24, `rand.Text()` is the purpose-built API - "Text returns a cryptographically random string using the standard RFC 4648 base32 alphabet for use when a secret string, token, password, or other text is needed", giving 26 characters with at least 128 bits of randomness and needing no separate encoding step. It returns a single `string` and no error - `token := rand.Text()`, not `token, err := rand.Text()`, which fails to compile with `assignment mismatch: 2 variables but rand.Text returns 1 value`
- `crypto/rand.Read` "never returns an error, and always fills b entirely" from Go 1.24: it calls `io.ReadFull` on `Reader` internally and crashes the program irrecoverably via a runtime fatal error, which `recover` cannot catch. Earlier releases returned a real error rather than failing silently. Keep the `err` check for older toolchains, but the branch has nothing useful to do - a fallback to `math/rand` there is itself the finding
- `math/rand.Seed` has been deprecated since Go 1.20 and a **no-op since Go 1.24** (restore with `GODEBUG=randseednop=0`). Between 1.20 and 1.23 an explicit `rand.Seed(time.Now().UnixNano())` was worse than useless: it forced the package off the ChaCha8 source onto the older generator. So a seeding line is not evidence of anything - triage the draw, not the line above it
- `math/rand/v2` is not the same generator with a new API. Go 1.22 replaced the Mitchell & Reeds LFSR source with `ChaCha8` and `PCG`, and the package documents `ChaCha8` as "a general-purpose source resistant to prediction" while `PCG` is "unfit for security-relevant purposes". The package-level warning still governs both: "This package's outputs might be easily predictable regardless of how it's seeded"
- `crypto/rand.Int(rand.Reader, max)` returns "a uniform random value in [0, max)" - exclusive of `max`, so pass `n` to get `0..n-1`. It masks and retries internally rather than taking a modulo, and it **panics** if `max <= 0` rather than returning an error
- `base64.URLEncoding` pads: 16 bytes encodes to 24 characters ending `==`, and 32 bytes to 44 ending `=`. Use `base64.RawURLEncoding` for a token that goes in a URL, since `=` is a reserved character
- Seeding a non-cryptographic generator from `crypto/rand` does not help - `rand.New(rand.NewSource(x))` is a deterministic stream once the seed is fixed, and it is separately documented as "not safe for concurrent use by multiple goroutines"
- `golang-jwt/jwt`'s HMAC signing methods enforce no minimum key length at all - even an empty `[]byte("")` key signs without error - so RFC 7518's floor (256 bits for HS256) has to be enforced at generation, not assumed from the library accepting the call. Generate the key with `crypto/rand`, sized to the algorithm, not a short literal

## Taint Sinks

`math/rand.Intn(`, `math/rand.Int63(`, `math/rand.Int31(`, `rand.New(rand.NewSource(`, `math/rand/v2` used for tokens, keys or nonces

## Remediation Steps

- Locate the draw rather than the seed - search for `math/rand` imports and for `Intn`, `Int63` and `rand.New` near token, key, password-reset or session code. A `rand.Seed` hit on Go 1.24+ is a dead line whose presence or removal changes no generated value
- Confirm the value is security-relevant before converting it. `math/rand` remains the correct choice for simulation and test data, and it is meaningfully faster than going to the kernel
- Replace with `rand.Text()` for tokens, `io.ReadFull(crypto/rand.Reader, b)` for raw keys and nonces, and `crypto/rand.Int` for bounded integers
- Size the output at 16 bytes or more for tokens and by the cipher for keys, then encode with `base64.RawURLEncoding` or `encoding/hex`
- Centralize generation in one reviewed helper so a new call site cannot reach for `math/rand` on a security path, and note that `math/rand.Read` was deprecated in Go 1.20 pointing at `crypto/rand.Read`
- Do not verify by inspecting the values. On Go 1.20+ the global `math/rand` is randomly seeded per process and on 1.22+ is ChaCha8-backed, so unfixed code passes any check for non-sequential output or for the absence of a fixed seed. Assert instead that the security path imports `crypto/rand`, and assert the length of what it returns
