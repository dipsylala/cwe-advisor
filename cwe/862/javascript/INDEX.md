# CWE-862: Missing Authorization - JavaScript

## LLM Guidance

In Express and similar Node.js frameworks, Missing Authorization typically appears as a route that runs authentication middleware confirming a valid session or JWT but has no follow-up check on role or resource ownership, or as a new route registered directly on the router without the shared authorization middleware applied to sibling routes. Fix by adding an explicit per-route authorization middleware for role checks, and, for resource-specific actions, a lookup scoped by the authenticated user so another user's record cannot be returned at all.

## Key Principles

- Treat session/JWT verification as authentication only; add a separate middleware or in-handler check for authorization (role, permission, or ownership)
- Apply authorization middleware at the router or route level (`router.post('/orders/:id/refund', requireAuth, requireRole('admin'), handler)`) so a route added without it is visibly missing the middleware in the route definition
- For resource-level checks, put the owner in the query (Mongoose `findOne({ _id: id, ownerId: req.user.id })`) rather than loading by ID and comparing afterwards - a role check alone is not sufficient when the action targets a specific user's data, and the scoped query keeps "not yours" and "not found" alike
- A scoped filter only holds if the values in it are scalars. Mongoose's `sanitizeFilter` (off by default) wraps any nested object whose key starts with `$` in a `$eq`; enable it, or coerce the identifier to a string before it reaches the filter, so a structured value cannot turn the predicate into an operator
- Do not rely on hiding client-side UI elements or trusting a role/permission value sent from the client in the request body
- Centralize role and permission definitions in one middleware module so route files import consistent checks instead of writing inline conditionals per handler
- Return 403 when the caller is authenticated and simply not permitted, and 401 when the credentials are missing, expired or invalid - a 401 must carry a `WWW-Authenticate` header. For a failed ownership check on a guessable id return the same 404 an unknown id would produce
- In NestJS the equivalent is a `CanActivate` guard applied with `@UseGuards()`. Guards run global first, then controller, then route, and every bound guard runs - a controller-level guard adds to a route-level one rather than being replaced by it. A guard returning `false` produces a `ForbiddenException` (403); throw your own exception for any other status

## Taint Sinks

`router.get()`, `router.post()`, `router.put()`, `router.delete()`, `app.use()`, `socket.on()`, `io.use()`, `socket.use()`, `@UseGuards()`, `req.user`

## Remediation Steps

- Locate - Identify Express routes, GraphQL resolvers, and Socket.IO event handlers that perform sensitive actions or return sensitive data. Confirm what populates `req.user` - Express defines no such property, and express-jwt has placed the payload on `req.auth` rather than `req.user` since v7
- Check for missing checks - Confirm the route only has authentication middleware with no role or ownership check before the handler executes
- Add role-based authorization - Insert a `requireRole('admin')` (or permission-based equivalent) middleware between authentication and the handler
- Add resource-based authorization - Scope the lookup by the authenticated user (`{ _id: id, ownerId: req.user.id }`) or a granted-access relationship, and return 404 when it finds nothing
- Apply consistently - Audit the router file to confirm every sensitive route uses the same middleware chain as comparable routes
- Harden configuration - Ensure authorization middleware runs after authentication middleware and before any route-specific logic that touches sensitive data. Socket.IO middleware registered with `io.use()` runs once per connection, not per event, so an event handler needs `socket.use()` (present since v1.6, absent in v3.0.0-v3.0.4) or an in-handler check
- Test - Write supertest/integration tests that call each route as an authenticated user lacking the required role and assert 403, and as a user who owns a different record and assert the same 404 an unknown id returns
