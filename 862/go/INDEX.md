# CWE-862: Missing Authorization - Go

## LLM Guidance

Go has no single dominant web framework, so Missing Authorization commonly appears as a handler that reads an authenticated user from `context.Context` but never checks that user's role or resource ownership before performing the operation, or as a new route registered directly on the mux without the shared authorization middleware wrapping it. Fix by adding an explicit authorization check (role or resource-ownership) at the start of every sensitive handler, and prefer wrapping handlers with a shared middleware function so the check cannot be forgotten on new routes.

## Key Principles

- Treat authentication (context has a valid user) and authorization (that user may perform this action) as separate steps; verify both explicitly in every handler
- Wrap sensitive routes with a shared authorization middleware (`func(http.Handler) http.Handler` or a `func(http.HandlerFunc) http.HandlerFunc` decorator) rather than duplicating checks inline, so a route registered without the wrapper is visible in the routing table
- For resource-level checks, load the resource and compare its owner or tenant field against the authenticated user's ID before performing the operation - do not rely on the URL parameter alone
- Return `http.StatusForbidden` (403) for authenticated-but-unauthorized requests and `http.StatusUnauthorized` (401) only when authentication itself is missing
- Keep authorization logic in one reusable package so role and ownership rules are defined once and unit-testable independent of HTTP
- Fail closed - if the authorization check errors or the required claim/role is absent, deny the request rather than defaulting to allow

## Taint Sinks

`http.HandleFunc()`, `mux.HandleFunc()` routes, gRPC service methods registered without a shared authorization middleware wrapper

## Remediation Steps

- Locate - Identify HTTP handlers, gRPC service methods, and background job entry points that perform sensitive actions or return sensitive data
- Check for missing checks - Confirm the handler reads the authenticated user from context but never checks role, permission, or resource ownership before proceeding
- Add the check - Call a shared authorization function and return 403 immediately if it returns false or an error
- Apply middleware to routing - Wrap the route registration with the shared authorization middleware instead of relying on a check inside the handler body alone
- Verify resource ownership - When the action targets a specific record, load it first and compare its owner or tenant ID to the authenticated user before mutating or returning it
- Audit route registration - Review the full mux/router setup to confirm every sensitive route is wrapped with the same middleware chain as its siblings
- Test - Write handler tests that call each route as an authenticated user lacking the required role or owning a different resource, and assert 403
