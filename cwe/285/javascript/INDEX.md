# CWE-285: Improper Authorization - JavaScript

## LLM Guidance

In Express applications, improper authorization occurs when route handlers perform operations without verifying the authenticated user has permission to do so. Authorization must be enforced in middleware applied before the handler, not inside the handler after data has already been fetched. Use authorization middleware (role-check functions, `express-jwt-permissions`, or framework-level guards) attached to individual routes or route groups.

## Key Principles

- Attach authorization middleware to routes rather than checking permissions inline inside handlers
- Check both authentication (identity) and authorization (permission) separately - a valid JWT is not sufficient
- Never derive role or permission from the request body or query string; read it from the verified token or session
- Apply a default-deny approach: unauthenticated or insufficiently privileged requests must be rejected before any business logic runs
- Cover all HTTP verbs - GET endpoints that expose sensitive data need the same authorization checks as POST/DELETE

## Taint Sinks

`router.get()`, `router.post()`, `router.put()`, `router.delete()`, `router.use()`, `req.body`, `req.query`, `req.user`, `jwt.verify()`

## Remediation Steps

- Identify unprotected routes - look for `router.get/post/put/delete` handlers that perform privileged operations without authorization middleware
- Create role-check middleware functions that verify the role or permissions from the decoded token/session. Confirm which property carries it: Express defines no `req.user`, and express-jwt has placed the payload on `req.auth` since v7
- Apply the middleware directly on the route or router group: `router.delete('/users/:id', requireRole('admin'), deleteUser)`
- For object-level authorization (IDOR), scope the lookup by the authenticated user rather than fetching by id and comparing afterwards, so a record belonging to someone else cannot be returned at all
- Test with tokens representing different roles and confirm lower-privileged requests are denied: 403 where a role or permission is the gate, and - for a guessable resource id - the same 404 an unknown id returns, matching body as well as status
- Apply `express-rate-limit` to sensitive routes to slow enumeration of authorization gaps
