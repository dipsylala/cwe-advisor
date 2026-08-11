# CWE-863: Incorrect Authorization - Go

## LLM Guidance

In Go handlers, Incorrect Authorization typically appears as a denylist role comparison (`if role != "admin"`), a check performed in one handler but forgotten in a sibling handler (e.g. checked on `GET /orders/{id}` but not `DELETE /orders/{id}`), or a role read from a client-supplied header or JWT claim without confirming it against server state. Because Go has no framework-enforced authorization layer, every handler must call an explicit, shared authorization function rather than repeating inline logic that can drift out of sync.

## Key Principles

- Centralize authorization in one function per resource/action and call it from every handler that touches that resource - do not repeat inline role checks per handler
- Use an allowlist of permitted roles or permissions (`switch` over expected values with a `default: deny`), never a denylist comparison like `role != "admin"`
- Load the resource and compare its owner/tenant field against the authenticated user ID resolved server-side (from session or verified JWT claims), never against a client-supplied field in the request body or query string
- Run the authorization check before any handler logic that reads or mutates state, and return `http.StatusForbidden` immediately on failure
- If roles come from a JWT, re-verify the token signature and re-derive the role from the verified claims on every request; do not cache a role from a prior request
- Default to denial: an unrecognized role, a missing claim, or an error resolving the resource must all result in a 403, not a fallthrough to success

## Remediation Steps

- Locate - Find handlers that read a role or permission (`r.Header.Get(...)`, JWT claims, session values) and compare it inline, and note which sibling handlers for the same resource skip the check
- Trace data flow - Confirm whether the role/permission value comes from a verified server-side source or an unverified client-supplied header, cookie, or body field
- Replace the unsafe pattern - Convert `!=` denylist comparisons to an explicit allowlist switch or a permission-lookup function shared across handlers
- Bind, encode, validate, or authorize - Add an ownership check that loads the resource and compares its owner field to the authenticated user ID before proceeding
- Break taint after allowlist validation - Assign the verified, server-resolved role to a fresh variable and use only that variable in the decision, not the raw claim or header value
- Harden configuration - Wrap all mutating routes with the shared authorization function so new handlers cannot bypass it by omission
- Test - Add table-driven tests covering an unexpected role value, a non-owner accessing another user's resource, and each HTTP method on the route, confirming all are denied

## Safe Pattern

```go
// SAFE: shared allowlist + ownership check applied before handler logic runs
package main

import "net/http"

// allowedRoles is an explicit allowlist; any role not listed is denied.
var allowedRoles = map[string]bool{
    "admin":  true,
    "editor": true,
}

type Order struct {
    ID      string
    OwnerID string
}

func loadOrder(id string) (*Order, error) {
    // Loads the order from the database; omitted for brevity.
    return &Order{ID: id, OwnerID: "user-123"}, nil
}

// authorizeOrderAccess resolves the caller's identity from the verified
// session/token (not from any client-supplied field) and checks both role
// and ownership before allowing the request to proceed.
func authorizeOrderAccess(r *http.Request, order *Order) bool {
    userID, role, ok := resolveVerifiedIdentity(r) // from session/JWT, server-side
    if !ok || !allowedRoles[role] {
        return false
    }
    if role == "admin" {
        return true
    }
    return order.OwnerID == userID
}

func deleteOrderHandler(w http.ResponseWriter, r *http.Request) {
    orderID := r.PathValue("id")
    order, err := loadOrder(orderID)
    if err != nil {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }

    if !authorizeOrderAccess(r, order) {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }

    // Delete logic runs only after both role and ownership are confirmed.
    w.WriteHeader(http.StatusNoContent)
}

func resolveVerifiedIdentity(r *http.Request) (userID, role string, ok bool) {
    // Verifies the session cookie or JWT signature and returns trusted
    // claims; never reads role/userID from an unverified header or body.
    return "user-123", "editor", true
}
```
