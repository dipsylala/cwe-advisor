# CWE-862: Missing Authorization - Go

## LLM Guidance

Go has no single dominant web framework, so Missing Authorization commonly appears as a handler that reads an authenticated user from `context.Context` but never checks that user's role or resource ownership before performing the operation, or as a new route registered directly on the mux without the shared authorization middleware wrapping it. Fix by adding an explicit authorization check (role or resource-ownership) at the start of every sensitive handler, and prefer wrapping handlers with a shared middleware function so the check cannot be forgotten on new routes.

## Key Principles

- Treat authentication (context has a valid user) and authorization (that user may perform this action) as separate steps; verify both explicitly in every handler
- Wrap sensitive routes with a shared authorization middleware (`func(http.Handler) http.Handler` or a `func(http.HandlerFunc) http.HandlerFunc` decorator) rather than duplicating checks inline, so a route registered without the wrapper is visible in the routing table
- For resource-level checks, scope the query by the authenticated user's ID rather than loading by primary key and comparing afterwards - a `WHERE id = ? AND owner_id = ?` lookup makes a record belonging to someone else indistinguishable from one that does not exist
- Return `http.StatusForbidden` (403) when a role or permission is the gate, and `http.StatusUnauthorized` (401) only when authentication itself is missing. For an ownership check on a guessable identifier return `http.StatusNotFound` for both the missing and the not-owned case, so the response does not reveal which one applies
- Keep authorization logic in one reusable package so role and ownership rules are defined once and unit-testable independent of HTTP
- Fail closed - if the authorization check errors or the required claim/role is absent, deny the request rather than defaulting to allow

## Taint Sinks

`http.HandleFunc()`, `mux.HandleFunc()` routes, gRPC service methods registered without a shared authorization middleware wrapper

## Remediation Steps

- Locate - Identify HTTP handlers, gRPC service methods, and background job entry points that perform sensitive actions or return sensitive data
- Check for missing checks - Confirm the handler reads the authenticated user from context but never checks role, permission, or resource ownership before proceeding
- Add the check - Call a shared authorization function and return 403 immediately if it returns false or an error
- Apply middleware to routing - Wrap the route registration with the shared authorization middleware instead of relying on a check inside the handler body alone
- Verify resource ownership - When the action targets a specific record, add the owner or tenant ID to the query's WHERE clause and treat no-rows as a 404, rather than loading by ID and comparing afterwards
- Audit route registration - Review the full mux/router setup to confirm every sensitive route is wrapped with the same middleware chain as its siblings
- Test - Write handler tests that call each route as an authenticated user lacking the required role, asserting 403, and as a user who owns a different resource, asserting the same 404 an unknown ID produces
