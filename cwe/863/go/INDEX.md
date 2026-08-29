# CWE-863: Incorrect Authorization - Go

## LLM Guidance

In Go handlers, Incorrect Authorization typically appears as an inline role comparison (`if role != "admin"`) duplicated per handler, a check performed in one handler but forgotten in a sibling handler (e.g. checked on `GET /orders/{id}` but not `DELETE /orders/{id}`), or a role read from a client-supplied header or JWT claim without confirming it against server state. Because Go has no framework-enforced authorization layer, every handler must call an explicit, shared authorization function rather than repeating inline logic that can drift out of sync.

## Key Principles

- Centralize authorization in one function per resource/action and call it from every handler that touches that resource - do not repeat inline role checks per handler
- Use an allowlist of permitted roles or permissions: a `switch` over the expected values whose `default` clause returns rather than merely existing, since a `switch` that falls out the bottom continues into the handler body. Read the shape before calling something a denylist - `role != "admin"` denies every unrecognised role and fails closed; the fail-open form is the one naming the roles to reject
- Load the resource and compare its owner/tenant field against the authenticated user ID resolved server-side (from session or verified JWT claims), never against a client-supplied field in the request body or query string
- Run the authorization check before any handler logic that reads or mutates state, and return `http.StatusForbidden` immediately on failure. Where the failure is ownership of a guessable identifier, answer with the same `http.StatusNotFound` an unknown identifier produces, matching body as well as status, so the two cases stay indistinguishable
- If roles come from a JWT, re-derive the role from the verified claims on every request rather than caching one. Verifying the signature is not sufficient on its own: pin the accepted algorithms (`golang-jwt`'s `jwt.WithValidMethods`) or a token can be presented under one the key was never meant for. Use `github.com/golang-jwt/jwt/v5` - `github.com/dgrijalva/jwt-go` is archived and CVE-2020-26160 has no patched release for it - and floor at v5.2.2 (CVE-2025-30204), or v4.5.1 if still on v4, where `ParseWithClaims` returned joined errors and a caller testing only for expiry could accept an invalid signature
- Default to denial: an unrecognized role or an error resolving the resource must result in a 403 rather than a fallthrough to success. A wholly missing or invalid credential is the 401 case instead, and a 401 must carry a `WWW-Authenticate` header

## Taint Sinks

`r.Header.Get()`, `r.Header.Values()`, `jwt.Parse()`, `jwt.ParseWithClaims()`, `jwt.WithValidMethods()`, `http.StatusForbidden`, `r.Context().Value()`

## Remediation Steps

- Locate - Find handlers that read a role or permission (`r.Header.Get(...)`, JWT claims, session values) and compare it inline, and note which sibling handlers for the same resource skip the check. `Header.Get` returns only the first value for a key and `""` for an absent one, so a duplicated role header collapses silently and an empty header is indistinguishable from none - use `Header.Values` where more than one may arrive
- Trace data flow - Confirm whether the role/permission value comes from a verified server-side source or an unverified client-supplied header, cookie, or body field
- Replace the unsafe pattern - Convert inline `!=` role comparisons to an explicit allowlist switch or a permission-lookup function shared across handlers
- Bind, encode, validate, or authorize - Add an ownership check that loads the resource and compares its owner field to the authenticated user ID before proceeding
- Break taint after allowlist validation - Assign the verified, server-resolved role to a fresh variable and use only that variable in the decision, not the raw claim or header value
- Harden configuration - Wrap all mutating routes with the shared authorization function so new handlers cannot bypass it by omission
- Test - Add table-driven tests covering an unexpected role value, a non-owner accessing another user's resource, and each HTTP method on the route, confirming all are denied
