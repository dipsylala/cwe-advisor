# CWE-347: Improper Verification of Cryptographic Signature - Go

## LLM Guidance

`golang-jwt/jwt` is vulnerable to algorithm confusion when the `Keyfunc` callback returns key material without checking `token.Method`, allowing an attacker to switch a token from RS256 to HS256 and sign it with the server's RSA public key treated as an HMAC secret. Always type-assert `token.Method` (or use `jwt.WithValidMethods(...)`) inside the keyfunc and reject anything unexpected before returning key material. For non-JWT signatures such as webhook payloads, compare the computed HMAC with `hmac.Equal()` or `subtle.ConstantTimeCompare()`, never `bytes.Equal()` or `==`, neither of which are constant-time.

## Key Principles

- Inside every `jwt.Keyfunc`, assert `token.Method` against the expected concrete type (`*jwt.SigningMethodRSA` for RS256) and return an error for anything else before returning key material
- Pass `jwt.WithValidMethods([]string{"RS256"})` as a parser option in addition to the keyfunc check, as defense in depth against future keyfunc changes
- Never return the same variable for both RSA public keys and HMAC secrets from a keyfunc that switches on `token.Header["alg"]`
- Resolve keys by `kid` only from a trusted, server-side keystore or JWKS - never trust a `jwk`/`x5c` value embedded in the token itself without independent verification
- Reject the `none` algorithm and weak algorithms; only accept the specific signing method your issuer uses
- Use `hmac.Equal()` (`crypto/hmac`) or `subtle.ConstantTimeCompare()` (`crypto/subtle`) for HMAC/signature comparisons - never `bytes.Equal()` or `==`

## Taint Sinks

`jwt.Parse()`/`jwt.ParseWithClaims()` with a `Keyfunc` missing `token.Method` check, `bytes.Equal()` on HMAC bytes

## Remediation Steps

- Locate - find `jwt.Parse(...)`, `jwt.ParseWithClaims(...)`, and any `Keyfunc` implementations, plus manual `hmac.New(...)` comparisons
- Trace data flow - check whether the keyfunc branches on `token.Header["alg"]` or `token.Method` without restricting to one expected type
- Replace the unsafe pattern - add a `token.Method` type assertion at the top of the keyfunc and return an error on mismatch; add `jwt.WithValidMethods` to the parser
- Bind, encode, validate, or authorize - resolve signing keys by `kid` from a trusted keystore and keep the algorithm expectation fixed regardless of the token's claims
- Harden configuration - set expected issuer/audience validators (`jwt.WithIssuer`, `jwt.WithAudience`) alongside the method restriction
- Test - re-sign a legitimate RS256 token as HS256 using the known public key as secret and confirm `jwt.Parse` returns an error

## Safe Pattern

```go
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// SAFE: keyfunc rejects any signing method other than RS256
keyFunc := func(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return rsaPublicKey, nil
}
token, err := jwt.Parse(tokenString, keyFunc, jwt.WithValidMethods([]string{"RS256"}))
if err != nil || !token.Valid {
	return fmt.Errorf("invalid token: %w", err)
}

// SAFE: webhook HMAC-SHA256 verification with constant-time comparison
mac := hmac.New(sha256.New, webhookSecret)
mac.Write(requestBody)
expected := mac.Sum(nil)
provided, err := hex.DecodeString(signatureHeader)
if err != nil || !hmac.Equal(expected, provided) {
	return fmt.Errorf("invalid webhook signature")
}
```
