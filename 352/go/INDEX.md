# CWE-352: Cross-Site Request Forgery (CSRF) - Go

## LLM Guidance

Go's `net/http` package has no built-in CSRF protection, so state-changing handlers (POST/PUT/DELETE/PATCH) registered on `http.ServeMux` or a router accept forged cross-site requests unless explicitly guarded. The primary fix on Go 1.25+ is `net/http.CrossOriginProtection`, which rejects cross-origin state-changing requests using Fetch metadata headers; otherwise use a synchronizer-token middleware, combined with `SameSite` cookie attributes as defense-in-depth. Check the `gorilla/csrf` version before recommending it: v1.7.3 fixed a Referer bypass (CVE-2025-24358) by enforcing same-origin, and that fix introduced CVE-2025-47909, where a host passed to `TrustedOrigins` is honoured over both HTTP and HTTPS because the scheme is never compared. CVE-2025-47909 has no fixed version, so migrate to the standard library or to the drop-in replacement `filippo.io/csrf/gorilla`. Never rely on `Origin`/`Referer` presence alone, and never accept state changes over GET.

## Key Principles

- Wrap state-changing routes with `net/http.CrossOriginProtection` (Go 1.25+), `filippo.io/csrf`, or a framework-native CSRF middleware; do not hand-roll token comparison. Where `gorilla/csrf` is already in use, treat it as a dependency to replace rather than to pin, since its latest release is still affected by CVE-2025-47909
- Ensure every handler that mutates state is registered on the CSRF-wrapped router, not a separate `http.ServeMux` or parallel API mux
- Set `SameSite: http.SameSiteStrictMode` or `SameSiteLaxMode` plus `Secure: true` and `HttpOnly: true` on session cookies as defense-in-depth, not as the sole control
- If validating `Origin`/`Referer` as a supplementary check, compare against an explicit allowlist of hosts, not just non-empty presence
- Never perform state changes on GET/HEAD requests; reserve them for safe, idempotent operations
- Reject requests missing or failing the CSRF token check with `http.StatusForbidden` before any business logic runs

## Taint Sinks

State-changing handlers (`http.MethodPost`/`Put`/`Delete`) registered outside `csrf.Protect()`-wrapped router

## Remediation Steps

- Locate - Find state-changing handlers using `r.Method == http.MethodPost` (or PUT/DELETE/PATCH) and confirm whether they are registered under a CSRF-protected router
- Trace data flow - Check every `http.HandleFunc`, router group, or secondary mux (API/mobile variants) that reaches the same authenticated actions; each must be wrapped
- Replace the unsafe pattern - Add `csrf.Protect([]byte(authKey), csrf.Secure(true), csrf.SameSite(csrf.SameSiteStrictMode))` (gorilla/csrf) around the router, or enable the router's built-in CSRF middleware; `authKey` must be 32 bytes loaded from a secret store (generate once with `securecookie.GenerateRandomKey(32)`), never a hardcoded literal
- Bind, encode, validate, or authorize - Embed the token with `csrf.TemplateField(r)`, which renders the hidden input under the name `gorilla.csrf.Token`; that exact name is the only one the middleware reads, so a hand-written field named `csrf_token` or `_csrf` fails validation while looking correct. For AJAX, send `csrf.Token(r)` in the `X-CSRF-Token` header
- Break taint after allowlist validation - When checking `Origin`/`Referer`, assign the parsed host to a new variable and compare it against a fixed allowlist before proceeding
- Harden configuration - Set `SameSite`, `Secure`, and `HttpOnly` on session cookies; confirm CSRF middleware applies globally, not per-route
- Test - Send requests with missing, forged, and expired tokens and confirm 403 responses; verify legitimate form/AJAX flows still succeed
