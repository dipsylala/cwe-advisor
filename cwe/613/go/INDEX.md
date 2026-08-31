# CWE-613: Insufficient Session Expiration - Go

## LLM Guidance

`gorilla/sessions`' `Options.MaxAge` left at its zero default produces a session-only cookie with no server-side expiry at all - it lives until the browser closes, which for a browser that never closes is unbounded. A JWT built with `golang-jwt/jwt/v5` has the same gap from the other direction: `RegisteredClaims.ExpiresAt` is entirely caller-set with no library-enforced ceiling, and by default the parser does not even *require* the claim to be present - a token minted with no `exp` at all validates successfully unless the caller explicitly opts into `jwt.WithExpirationRequired()`. Go has no built-in revocation for either: closing the gap for anything that must be invalidated before its natural expiry means building a store of your own.

## Key Principles

- `gorilla/sessions`' `Options.MaxAge` defaults to `0` - a session-only cookie with no expiry enforced server-side, gone only when the browser closes. Set it explicitly (a positive number of seconds) for both an idle-refresh cadence and an absolute cap; the package has no separate primitive for either, so both are application convention layered on the one field
- Do not assume a `golang-jwt/jwt/v5` token without an `exp` claim fails validation - `Validator.Validate()`'s own documentation states the claim is optional by default, so a token minted with no `ExpiresAt` set passes unless the parser was built with `jwt.WithExpirationRequired()`. Require it explicitly rather than relying on the default
- The library enforces no maximum lifetime on `ExpiresAt` - it is a caller-set `*jwt.NumericDate` via `jwt.NewNumericDate(t)`, so a hand-picked date a century out is exactly as valid as a sensible one
- There is no built-in revocation path. The `jti` field exists on `RegisteredClaims` per RFC 7519, but golang-jwt implements no lookup against it - closing this gap means your own `jti`-keyed store checked before trusting the token, or a short-lived access token paired with a separately revocable refresh token
- The predecessor library, `dgrijalva/jwt-go` (archived), had a documented bug where a malformed `exp` claim silently skipped expiration checking rather than failing - a reason to use `RegisteredClaims` rather than writing a custom claims type that re-implements expiration parsing by hand
- Per RFC 6265 §4.1.2.2, `http.Cookie.MaxAge` takes precedence over `Expires` when both are set, and neither set means the user agent keeps the cookie only until "the current session is over" - the same gap as gorilla/sessions' unset `MaxAge`, since gorilla builds on this exact mechanism

## Taint Sinks

`sessions.Options{}` with `MaxAge` left unset or `0` on a security-relevant session, `jwt.RegisteredClaims{}` with no `ExpiresAt` set, a JWT parser built without `jwt.WithExpirationRequired()`, a hand-rolled claims struct re-implementing `exp` parsing instead of embedding `RegisteredClaims`

## Remediation Steps

- Locate - find `sessions.Options` construction and `jwt.RegisteredClaims`/custom claims struct construction for issued tokens
- Trace what the session or token authorizes, to size the lifetime to the risk
- Identify the unsafe pattern - `MaxAge` left at its zero default, `ExpiresAt` omitted or set implausibly far out, or a parser missing `WithExpirationRequired()`
- Replace with an explicit `MaxAge` and `ExpiresAt` sized to the risk, and add `jwt.WithExpirationRequired()` to the parser
- Bind, encode, validate, or authorize - for pre-expiry revocation, check the token's `jti` against a server-side store, or move to a short-lived access token with a separately revocable refresh token
- Harden configuration - re-`Save` the session on activity for idle/rolling behavior, since gorilla/sessions has no primitive for it beyond calling `Save` again
- Test - confirm a token with no `exp` claim is rejected, and that a session or token issued before a shortened lifetime is rejected once the new, shorter window passes
