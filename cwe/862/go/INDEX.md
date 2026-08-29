# CWE-862: Missing Authorization - Go

## LLM Guidance

Go has no single dominant web framework, so Missing Authorization commonly appears as a handler that reads an authenticated user from `context.Context` but never checks that user's role or resource ownership before performing the operation, or as a new route registered directly on the mux without the shared authorization middleware wrapping it. Fix by adding an explicit authorization check (role or resource-ownership) at the start of every sensitive handler, and prefer wrapping handlers with a shared middleware function so the check cannot be forgotten on new routes.

## Key Principles

- Treat authentication (context has a valid user) and authorization (that user may perform this action) as separate steps; verify both explicitly in every handler
- Wrap sensitive routes with a shared authorization middleware (`func(http.Handler) http.Handler` or a `func(http.HandlerFunc) http.HandlerFunc` decorator) rather than duplicating checks inline, so the wrapper's absence is visible at the point of registration - `ServeMux` exposes no way to enumerate what it holds, so the registration site is the only place the omission shows
- For resource-level checks, scope the query by the authenticated user's ID rather than loading by primary key and comparing afterwards - a `WHERE id = ? AND owner_id = ?` lookup makes a record belonging to someone else answer alike to one that does not exist. The placeholder is driver-specific - `?` for MySQL and SQLite, `$1` for `lib/pq` - and the no-rows result to test for is `sql.ErrNoRows`
- Return `http.StatusForbidden` (403) when the caller is authenticated and simply not permitted, and `http.StatusUnauthorized` (401) when credentials are missing, expired or invalid - a 401 must carry a `WWW-Authenticate` header, which `http.Error` will not add for you. For an ownership check on a guessable identifier return `http.StatusNotFound` for both the missing and the not-owned case, matching body as well as status
- gRPC has no HTTP status to return: every RPC answers `200` with the outcome in the `grpc-status` trailer. Enforce there with a `grpc.UnaryServerInterceptor`/`StreamServerInterceptor` installed via `grpc.ChainUnaryInterceptor`, denying with `status.Errorf(codes.PermissionDenied, ...)` - or `codes.Unauthenticated` where the caller could not be identified
- Keep authorization logic in one reusable package so role and ownership rules are defined once and unit-testable independent of HTTP
- Fail closed - if the authorization check errors or the required claim/role is absent, deny the request rather than defaulting to allow

## Taint Sinks

`http.HandleFunc()`, `http.Handle()`, `ServeMux.HandleFunc()`, `grpc.ChainUnaryInterceptor()`, `status.Errorf()`, `codes.PermissionDenied`, `sql.ErrNoRows`

## Remediation Steps

- Locate - Identify HTTP handlers, gRPC service methods, and background job entry points that perform sensitive actions or return sensitive data
- Check for missing checks - Confirm the handler reads the authenticated user from context but never checks role, permission, or resource ownership before proceeding
- Add the check - Call a shared authorization function and deny immediately if it returns false or an error: 403 over HTTP, `codes.PermissionDenied` over gRPC
- Apply middleware to routing - Wrap the route registration with the shared authorization middleware instead of relying on a check inside the handler body alone
- Verify resource ownership - When the action targets a specific record, add the owner or tenant ID to the query's WHERE clause and treat no-rows as a 404, rather than loading by ID and comparing afterwards
- Audit route registration - Review the full mux/router setup to confirm every sensitive route is wrapped with the same middleware chain as its siblings. On Go 1.22+ a `ServeMux` pattern can name its method (`"DELETE /orders/{id}"`); before that, or under `GODEBUG=httpmuxgo121=1`, one registration answers every method, so a check written for `GET` also governs the write paths reaching it
- Test - Write `httptest` handler tests that call each route as an authenticated user lacking the required role, asserting 403, and as a user who owns a different resource, asserting the same 404 an unknown ID produces. Registering a pattern with `"GET"` also registers `"HEAD"`, so cover that method too
