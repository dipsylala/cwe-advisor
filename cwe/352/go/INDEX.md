# CWE-352: Cross-Site Request Forgery (CSRF) - Go

## LLM Guidance

Go's `net/http` package has no built-in CSRF protection, so state-changing handlers (POST/PUT/DELETE/PATCH) registered on `http.ServeMux` or a router accept forged cross-site requests unless explicitly guarded. The primary fix on Go 1.25.1+ is `net/http.CrossOriginProtection`, which rejects cross-origin state-changing requests using Fetch metadata headers; on older releases `filippo.io/csrf` is the same check as a module. Combine either with `SameSite` cookie attributes as defense-in-depth. Check the `gorilla/csrf` version before recommending it: v1.7.3 fixed a Referer bypass (CVE-2025-24358) by enforcing same-origin, and that fix introduced CVE-2025-47909, where a host passed to `TrustedOrigins` is honoured over both HTTP and HTTPS because the scheme is never compared. CVE-2025-47909 has no fixed version, so migrate to the standard library or to the drop-in replacement `filippo.io/csrf/gorilla`. Never rely on `Origin`/`Referer` presence alone, and never accept state changes over GET.

## Key Principles

- Wrap state-changing routes with `net/http.CrossOriginProtection` (Go 1.25.1+), `filippo.io/csrf` on older releases - its `gorilla` subpackage only where the code already calls the gorilla API - or a framework-native CSRF middleware; do not hand-roll token comparison. `Handler(h)` wraps a mux or handler where the routes are registered; where the change is confined to one handler, call `Check(r)` on a package-level `*CrossOriginProtection` inside it and deny on a non-nil error. Either way the protection has to be in the delivered change - removing an existing Origin check and leaving a comment for a wrap elsewhere ships the sink unprotected. Require 1.25.1 rather than 1.25.0: in 1.25.0 `AddInsecureBypassPattern` also exempted requests that `ServeMux` would have *redirected* to the pattern, exempting more than intended (CVE-2025-47910). Where `gorilla/csrf` is already in use, replace it rather than pin it: its latest release is still affected
- `filippo.io/csrf/gorilla` is API-compatible with `gorilla/csrf` but not behavior-compatible: it drops tokens and cookies entirely for the same Fetch-metadata check as the standard library, so its `Token()`/`TemplateField()` are deprecated no-op stubs kept only so old call sites still compile. A migration that keeps rendering `csrf.TemplateField(r)` into a form gets a stub value, not a working token
- Ensure every handler that mutates state is registered on the CSRF-wrapped router, not a separate `http.ServeMux` or parallel API mux
- Set `SameSite: http.SameSiteStrictMode` or `SameSiteLaxMode` plus `Secure: true` and `HttpOnly: true` on session cookies as defense-in-depth, not as the sole control
- If validating `Origin`/`Referer` as a supplementary check, compare against an explicit allowlist of hosts, not just non-empty presence
- Never perform state changes on GET/HEAD requests; reserve them for safe, idempotent operations. Where a GET exists so a link can reach the action, keep the GET as a confirmation page that POSTs through the protected handler rather than re-registering the route as `DELETE` and breaking the link (see the root entry)
- Reject requests missing or failing the CSRF token check with `http.StatusForbidden` before any business logic runs

## Taint Sinks

State-changing handlers (`http.MethodPost`/`Put`/`Delete`) registered outside the wrapped handler tree - whether the wrapper is `CrossOriginProtection.Handler()`, a router's own CSRF middleware, or `csrf.Protect()` in existing gorilla code

## Remediation Steps

- Locate - Find state-changing handlers using `r.Method == http.MethodPost` (or PUT/DELETE/PATCH) and confirm whether they are registered under a CSRF-protected router
- Trace data flow - Check every `http.HandleFunc`, router group, or secondary mux (API/mobile variants) that reaches the same authenticated actions; each must be wrapped
- Replace the unsafe pattern - wrap the mux where the server is started: `p := http.NewCrossOriginProtection()` then `http.ListenAndServe(addr, p.Handler(mux))`. On Gin and Echo the wrapper only takes effect if it is what starts the server - `gin.Engine.Run()` builds its own `http.Server` around `engine.Handler()` and `echo.Echo.Start()` passes the `Echo` itself, so a handler wrapped and then started with `r.Run()` compiles, serves every route and applies no check. Pass the wrapped handler to `http.ListenAndServe` or `http.Server{Handler: ...}`
- Bind, encode, validate, or authorize - a token scheme already threaded through the templates is worth keeping, but it is not what closes this finding, and `gorilla/csrf` is not the library to add to close it (see CVE-2025-47909 above)
- Break taint after allowlist validation - When checking `Origin`/`Referer`, assign the parsed host to a new variable and compare it against a fixed allowlist before proceeding
- Harden configuration - Set `SameSite`, `Secure`, and `HttpOnly` on session cookies; confirm CSRF middleware applies globally, not per-route
- Test - replay one captured state-changing request three times, altering nothing but the headers: unchanged (expect the normal 2xx), with `Sec-Fetch-Site: cross-site`, and with `Sec-Fetch-Site: same-site`. Both header cases must return 403 *and* leave the record unchanged - assert on the data, since a handler can reject the response after performing the write. The `same-site` case is the one worth keeping: it is refused here while a `SameSite=Strict` cookie would still have been sent, so it is what distinguishes the check from the cookie flag. Verify legitimate form and AJAX flows still succeed
