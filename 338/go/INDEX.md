# CWE-338: Use of Cryptographically Weak PRNG - Go

## LLM Guidance

`math/rand` and `math/rand/v2` in Go implement fast, deterministic pseudo-random algorithms that are not cryptographically secure, regardless of how they are seeded: enough observed output lets an attacker reconstruct the generator's internal state and predict every future value. Since Go 1.20 the global `math/rand` source auto-seeds from OS randomness at startup, but this only removes a fixed or guessable seed - it does not make the algorithm itself safe for security use. Replace any `math/rand`/`math/rand/v2` call in a security-sensitive path with `crypto/rand`.

## Key Principles

- Treat `math/rand` and `math/rand/v2` as unsuitable for tokens, session IDs, CSRF tokens, encryption keys, nonces, and password reset codes, regardless of Go version or auto-seeding
- Use `crypto/rand.Reader` (via `io.ReadFull` or `rand.Read`) for all security-sensitive random bytes
- Do not seed `math/rand` with a `crypto/rand` value and continue drawing from it - the output remains a deterministic function of a now-fixed seed and is reconstructable from observed values
- Audit helper functions written for non-security use (shuffling, sampling) that later get reused for a security-relevant selection, such as choosing a verification question or partitioning a feature flag
- When reducing `crypto/rand` output to a smaller range (OTP digits), use `crypto/rand.Int(rand.Reader, big.NewInt(n))` rather than `%` on raw bytes, which introduces modulo bias
- `math/rand`/`math/rand/v2` remain the correct choice for simulations, games, and reproducible test fixtures - the fix is scoping their use away from security code, not removing them entirely

## Remediation Steps

- Locate - search for `math/rand`, `"math/rand/v2"`, `rand.Intn`, `rand.Int63`, and `rand.Float64` in token, key, nonce, or credential-generation code
- Trace data flow - confirm the value protects an authentication, authorization, or cryptographic operation rather than being test or simulation data
- Replace the unsafe pattern - substitute `crypto/rand.Reader` reads (or `crypto/rand.Int` for bounded ranges) for the `math/rand` call
- Verify entropy sizing - use at least 16 bytes for tokens/CSRF values and 32 bytes for encryption keys before encoding
- Harden configuration - remove any manual seeding of `math/rand` in security-adjacent packages and keep `crypto/rand` usage in a single reviewed helper
- Test - confirm tokens are unpredictable across restarts and that no security code path still imports `math/rand` or `math/rand/v2`

## Safe Pattern

```go
// SAFE: cryptographically secure CSRF token
import (
    "crypto/rand"
    "encoding/hex"
)

func generateCSRFToken() (string, error) {
    b := make([]byte, 32) // 256 bits
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}
```
