# CWE-287: Improper Authentication - Go

## LLM Guidance

Go has no built-in authentication framework, so login, session, and token verification logic is entirely application code and carries the full risk of the bypass. The most common concrete failure is a JWT verified with `golang-jwt/jwt` where the `keyFunc` callback returns a key without checking `token.Method`, letting an attacker switch the header to `alg: none` or from RS256 to HS256 and forge a valid-looking signature - the class of bug behind several real CVEs in Go JWT libraries. Fix by asserting the expected signing method inside `keyFunc` and by pinning valid methods on the parser, and by comparing passwords with a constant-time hash comparison.

## Key Principles

- In the `keyFunc` passed to `jwt.ParseWithClaims`/`jwt.Parse`, assert the concrete signing method before returning a key: `if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { return nil, fmt.Errorf(...) }` - without this check, the attacker-controlled `alg` header decides how the token is verified.
- Prefer the `jwt.WithValidMethods([]string{"HS256"})` parser option (`golang-jwt/jwt/v5`) in addition to the `keyFunc` check, so parsing fails before a key is even resolved for a disallowed algorithm.
- Never accept `jwt.SigningMethodNone` (`alg: none`) - do not add it to any valid-methods list or unconditionally trust `token.Method.Alg()` from the header.
- Compare passwords with a constant-time, salted hash function such as `golang.org/x/crypto/bcrypt` (`bcrypt.CompareHashAndPassword`), never `==` on plaintext or a fast unsalted hash.
- Since there is no framework-enforced auth layer, apply the authentication check as HTTP middleware wrapping every protected handler, not as an ad hoc check duplicated per handler.
- Store JWT/HMAC signing secrets via environment variables or a secret manager, generated with sufficient entropy (32+ random bytes for HS256).

## Remediation Steps

- Locate - Find `jwt.Parse`/`jwt.ParseWithClaims` calls and their `keyFunc` implementations, and password comparison code in login handlers
- Trace data flow - Follow the token from the `Authorization` header into `keyFunc`, and the submitted password into the comparison function
- Replace the unsafe pattern - Add a `token.Method` type assertion inside `keyFunc` and/or `jwt.WithValidMethods`; replace plaintext/`==` password comparisons with `bcrypt.CompareHashAndPassword`
- Bind, encode, validate, or authorize - Accept only the specific `SigningMethodHMAC`/`SigningMethodRSA` variant the issuer actually uses; reject all others, including `none`
- Break taint after allowlist validation - Use only the `*jwt.Token` returned after `Parse`/`ParseWithClaims` succeeds and `token.Valid` is true for identity decisions; never read claims from a token that failed parsing
- Harden configuration - Centralize the authentication check in HTTP middleware applied to every protected route
- Test - Write a test that submits a token re-signed with `alg: none` or with the RS256 public key reused as an HS256 secret, and confirm `ParseWithClaims` returns an error

## Safe Pattern

```go
// SAFE: keyFunc pins the expected signing method; alg:none and algorithm-swap attacks fail
import (
    "fmt"
    "github.com/golang-jwt/jwt/v5"
)

var hmacSecret = []byte(mustGetEnv("JWT_SECRET"))

func verifyToken(tokenString string) (*jwt.Token, error) {
    claims := jwt.MapClaims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
        }
        return hmacSecret, nil
    }, jwt.WithValidMethods([]string{"HS256"}))

    if err != nil || !token.Valid {
        return nil, fmt.Errorf("invalid token: %w", err)
    }
    return token, nil
}
```
