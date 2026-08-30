# CWE-347: Improper Verification of Cryptographic Signature - Go

## LLM Guidance

`golang-jwt/jwt` is vulnerable to algorithm confusion when the `Keyfunc` callback returns key material without checking `token.Method`, allowing an attacker to switch a token from RS256 to HS256 and sign it with the server's RSA public key treated as an HMAC secret. The library's own README carries a security notice on exactly this point. Always type-assert `token.Method` (or use `jwt.WithValidMethods(...)`) inside the keyfunc and reject anything unexpected before returning key material. For non-JWT signatures such as webhook payloads, compare the computed HMAC with `hmac.Equal()` or `subtle.ConstantTimeCompare()`, never `bytes.Equal()` or `==`, neither of which are constant-time.

## Key Principles

- Confirm the import path is `github.com/golang-jwt/jwt/v5` (or `/v4`) - the unversioned `github.com/golang-jwt/jwt` resolves to the abandoned v3 line, and the predecessor `github.com/dgrijalva/jwt-go` is archived and unmaintained; a finding against either import is a dependency upgrade, not just a code fix
- Inside every `jwt.Keyfunc`, assert `token.Method` against the expected concrete type (`*jwt.SigningMethodRSA` for RS256) and return an error for anything else before returning key material
- Pass `jwt.WithValidMethods([]string{"RS256"})` as a parser option in addition to the keyfunc check, as defense in depth against future keyfunc changes - available on both the `/v4` and `/v5` import paths
- Never return the same variable for both RSA public keys and HMAC secrets from a keyfunc that switches on `token.Header["alg"]`
- Resolve keys by `kid` only from a trusted, server-side keystore or JWKS - never trust a `jwk`/`x5c` value embedded in the token itself without independent verification
- Reject the `none` algorithm and weak algorithms; only accept the specific signing method your issuer uses
- Use `hmac.Equal()` (`crypto/hmac`) or `subtle.ConstantTimeCompare()` (`crypto/subtle`) for HMAC/signature comparisons - never `bytes.Equal()` or `==`

## Taint Sinks

`jwt.Parse()`/`jwt.ParseWithClaims()` with a `Keyfunc` missing `token.Method` check, `bytes.Equal()` on HMAC bytes

## Remediation Steps

- Locate - find `jwt.Parse(...)`, `jwt.ParseWithClaims(...)`, and any `Keyfunc` implementations, plus manual `hmac.New(...)` comparisons
- Trace data flow - check whether the keyfunc branches on `token.Header["alg"]` or `token.Method` without restricting to one expected type
- Replace the unsafe pattern - add a `token.Method` type assertion at the top of the keyfunc and return an error on mismatch; add `jwt.WithValidMethods` to the parser, and check both the returned error and `token.Valid`
- Bind, encode, validate, or authorize - resolve signing keys by `kid` from a trusted keystore and keep the algorithm expectation fixed regardless of the token's claims
- Harden configuration - set expected issuer/audience validators (`jwt.WithIssuer`, `jwt.WithAudience`) alongside the method restriction; golang-jwt validates `exp` only when the claim is present but does not require it by default, so also add `jwt.WithExpirationRequired()` or a token without `exp` passes unexpired forever
- Test - re-sign a legitimate RS256 token as HS256 using the known public key as secret and confirm `jwt.Parse` returns an error
