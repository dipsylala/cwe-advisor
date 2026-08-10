# CWE-352: Cross-Site Request Forgery (CSRF) - Go

## LLM Guidance

Go's `net/http` package has no built-in CSRF protection, so state-changing handlers (POST/PUT/DELETE/PATCH) registered on `http.ServeMux` or a router accept forged cross-site requests unless explicitly guarded. The primary fix is a synchronizer-token middleware such as the maintained `gorilla/csrf` package (or a framework-native equivalent like Echo's `middleware.CSRFWithConfig`), combined with `SameSite` cookie attributes as defense-in-depth. Never rely on `Origin`/`Referer` presence alone, and never accept state changes over GET.

## Key Principles

- Wrap state-changing routes with a CSRF token middleware (`gorilla/csrf.Protect(...)` or framework-native CSRF middleware); do not hand-roll token comparison
- Ensure every handler that mutates state is registered on the CSRF-wrapped router, not a separate `http.ServeMux` or parallel API mux
- Set `SameSite: http.SameSiteStrictMode` or `SameSiteLaxMode` plus `Secure: true` and `HttpOnly: true` on session cookies as defense-in-depth, not as the sole control
- If validating `Origin`/`Referer` as a supplementary check, compare against an explicit allowlist of hosts, not just non-empty presence
- Never perform state changes on GET/HEAD requests; reserve them for safe, idempotent operations
- Reject requests missing or failing the CSRF token check with `http.StatusForbidden` before any business logic runs

## Remediation Steps

- Locate - Find state-changing handlers using `r.Method == http.MethodPost` (or PUT/DELETE/PATCH) and confirm whether they are registered under a CSRF-protected router
- Trace data flow - Check every `http.HandleFunc`, router group, or secondary mux (API/mobile variants) that reaches the same authenticated actions; each must be wrapped
- Replace the unsafe pattern - Add `csrf.Protect([]byte(authKey), csrf.Secure(true), csrf.SameSite(csrf.SameSiteStrictMode))` (gorilla/csrf) around the router, or enable the router's built-in CSRF middleware
- Bind, encode, validate, or authorize - Embed `csrf.Token(r)` in forms via a hidden field or send it as a header for AJAX/fetch calls; verify server-side rejects mismatched or missing tokens
- Break taint after allowlist validation - When checking `Origin`/`Referer`, assign the parsed host to a new variable and compare it against a fixed allowlist before proceeding
- Harden configuration - Set `SameSite`, `Secure`, and `HttpOnly` on session cookies; confirm CSRF middleware applies globally, not per-route
- Test - Send requests with missing, forged, and expired tokens and confirm 403 responses; verify legitimate form/AJAX flows still succeed

## Safe Pattern

```go
// SAFE: gorilla/csrf synchronizer token middleware wrapping state-changing routes
package main

import (
    "net/http"

    "github.com/gorilla/csrf"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/transfer", transferHandler)

    csrfMiddleware := csrf.Protect(
        []byte("32-byte-long-auth-key-from-secret-store"),
        csrf.Secure(true),
        csrf.SameSite(csrf.SameSiteStrictMode),
    )

    http.ListenAndServe(":8080", csrfMiddleware(mux))
}

func transferHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    // csrf.Protect already validated the token before this handler runs
    w.Write([]byte("transfer complete"))
}
```
