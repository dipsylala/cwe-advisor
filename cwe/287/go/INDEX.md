# CWE-287: Improper Authentication - Go

## LLM Guidance

Go has no built-in authentication framework, so login, session, and token verification logic is entirely application code and carries the full risk of the bypass. The most common concrete failure is a JWT verified with `golang-jwt/jwt` where the `keyFunc` callback returns a key without checking `token.Method`, letting an attacker switch the header to `alg: none` or from RS256 to HS256 and forge a valid-looking signature - the class of bug behind several real CVEs in Go JWT libraries. Fix by asserting the expected signing method inside `keyFunc` and by pinning valid methods on the parser, and by comparing passwords with a constant-time hash comparison.

## Key Principles

- In the `keyFunc` passed to `jwt.ParseWithClaims`/`jwt.Parse`, assert the concrete signing method before returning a key: `if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { return nil, fmt.Errorf(...) }` - without this check, the attacker-controlled `alg` header decides how the token is verified.
- Prefer the `jwt.WithValidMethods([]string{"HS256"})` parser option (`golang-jwt/jwt/v5`) in addition to the `keyFunc` check, so parsing fails before a key is even resolved for a disallowed algorithm.
- Never accept `jwt.SigningMethodNone` (`alg: none`) - do not add it to any valid-methods list or unconditionally trust `token.Method.Alg()` from the header. The library does not accept one by default: verification requires the key to be the `jwt.UnsafeAllowNoneSignatureType` constant and otherwise returns `NoneSignatureTypeDisallowedError`, so what to look for is code that opted in.
- Pin the library while fixing: `golang-jwt/jwt` v5.2.2 or later, or v4.5.2 on the v4 line. CVE-2025-30204 is an excessive memory allocation while splitting a token header; on v4 its fix supersedes 4.5.1's for CVE-2024-51744.
- Compare passwords with a constant-time, salted hash function such as `golang.org/x/crypto/bcrypt` (`bcrypt.CompareHashAndPassword`), never `==` on plaintext or a fast unsalted hash.
- Run `bcrypt.CompareHashAndPassword` on the lookup-miss branch too, against a dummy hash derived at start-up with `bcrypt.GenerateFromPassword` at the same cost: returning as soon as `lookupUser` fails answers without ever reaching bcrypt, where a wrong password pays the full cost, which enumerates usernames.
- Fall back to that dummy when the stored `PasswordHash` is empty (an SSO-only row) as well - `CompareHashAndPassword` returns `ErrHashTooShort` immediately for an empty or malformed hash, so a blank or pasted placeholder times that case instead of hiding it, and a literal at a different cost than `bcrypt.DefaultCost` is a timing gap of its own.
- `gorilla/sessions` has no identifier rotation, and `store.New` is not one. Its doc comment gives the only difference from `store.Get` as decoding twice versus reusing the decoded session; both read an existing request cookie, decode it and set `IsNew = false` on success, so neither discards a session an attacker planted before login.
- Rotate by hand at successful login instead. With a server-side store such as `FilesystemStore`, set `session.Options.MaxAge = -1` and `Save` to erase the stored record, then save a fresh session whose `ID` is empty, which is the condition on which `Save` mints a new random one. With `CookieStore` there is no server-side identifier at all - the cookie is the session - so replace `session.Values` wholesale rather than adding the authenticated user to values decoded from the planted cookie. Set `Secure`, `HttpOnly` and `SameSite` on `sessions.Options` at the same point.
- This stays application code: `gorilla/sessions` last released v1.4.0 in August 2024 and closed its identifier-regeneration request (issue #235) unfixed.
- Since there is no framework-enforced auth layer, apply the authentication check as HTTP middleware wrapping every protected handler, not as an ad hoc check duplicated per handler.
- Store JWT/HMAC signing secrets via environment variables or a secret manager, generated with sufficient entropy (32+ random bytes for HS256).

## Taint Sinks

`jwt.Parse()`/`ParseWithClaims()` with unchecked `keyFunc`, `==` plaintext password comparison

## Remediation Steps

- Locate - Find `jwt.Parse`/`jwt.ParseWithClaims` calls and their `keyFunc` implementations, and password comparison code in login handlers
- Trace data flow - Follow the token from the `Authorization` header into `keyFunc`, and the submitted password into the comparison function
- Replace the unsafe pattern - Add a `token.Method` type assertion inside `keyFunc` and/or `jwt.WithValidMethods`; replace plaintext/`==` password comparisons with `bcrypt.CompareHashAndPassword`
- Bind, encode, validate, or authorize - Accept only the specific `SigningMethodHMAC`/`SigningMethodRSA` variant the issuer actually uses; reject all others, including `none`
- Break taint after allowlist validation - Use only the `*jwt.Token` returned after `Parse`/`ParseWithClaims` succeeds and `token.Valid` is true for identity decisions; never read claims from a token that failed parsing
- Harden configuration - Centralize the authentication check in HTTP middleware applied to every protected route
- Test - Write a test that submits a token re-signed with `alg: none` or with the RS256 public key reused as an HS256 secret, and confirm `ParseWithClaims` returns an error; time a right password, a wrong password, an unknown username, and a row with an empty `PasswordHash` and assert all four are within noise of each other
