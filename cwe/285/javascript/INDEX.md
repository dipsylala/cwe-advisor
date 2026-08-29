# CWE-285: Improper Authorization - JavaScript

## LLM Guidance

In Express applications, improper authorization occurs when a route handler performs a privileged operation without verifying the caller may do so. Attach the coarse role or permission check as middleware ahead of the handler, and put the per-record check at the data access call, since a route-level guard has no resource to inspect. Express supplies no authorization primitives of its own, so the guard is either hand-written or from a package - name the package and check that it is still maintained.

## Key Principles

- Express defines no `req.user`, and the packages that populate it disagree: Passport assigns to `req.user`, `express-jwt` has placed the payload on `req.auth` since v7 (`requestProperty` overrides it), and `express-jwt-permissions` defaults to reading `req.user`. Wired together out of the box, that guard reads a property the verifier never wrote and enforces nothing - confirm which property carries the payload before writing the check
- `express-jwt-permissions` last published in September 2022. Prefer a guard written against the verified token, or the framework's own mechanism where one exists - NestJS `CanActivate` with `@UseGuards()`, a Fastify `preValidation` hook
- `express-jwt` requires `algorithms` and throws `RangeError` at construction without it, which prevents an algorithm-downgrade; set `audience` and `issuer` too. The underlying `jsonwebtoken` floor is **9.0.0** - it fixes CVE-2022-23529 (RCE through a crafted `secretOrPublicKey`) and CVE-2022-23540 (verification falling back to `alg: none` with a falsy secret) - and is what `express-jwt` 8.0.0 was released for
- Never derive a role or permission from the request body or query string; read it from the verified token or session
- Middleware runs in registration order, so a router mounted before the authentication middleware is registered runs with no principal at all, and the guard then throws on `undefined` rather than denying
- A denial is not a status code by itself: an error thrown in a handler reaches the client as 500 unless it carries `.status`/`.statusCode`, and a library that throws a 403-bearing error still needs an error-handling middleware registered after the routes to render it. Express 5, now the default install, forwards a rejected promise from an `async` handler to that middleware; Express 4 does not
- For object-level authorization (IDOR), scope the lookup by the authenticated user - `findOne({ where: { id, userId } })` in Sequelize, `findFirst({ where: { id, userId } })` in Prisma - rather than fetching by id and comparing afterwards
- Cover all HTTP verbs: a `GET` exposing the same record needs the check its `DELETE` has
- These route and token APIs match guarded and unguarded code alike, so the finding is a route registered with no guard between the path and the handler - read the argument list rather than counting hits

## Taint Sinks

`router.get()`, `router.post()`, `router.put()`, `router.delete()`, `app.use()`, `req.params.id`, `req.body`, `req.query`, `req.user`, `req.auth`, `jwt.decode()`, `jwt.verify()`

## Remediation Steps

- Identify unprotected routes - `router.get/post/put/delete` handlers that perform privileged operations with no guard argument between the path and the handler
- Create role-check middleware that reads the role or permissions from the decoded token or session, on the property the verification middleware actually sets
- Apply the middleware directly on the route or router group: `router.delete('/users/:id', requireRole('admin'), deleteUser)`
- Confirm the authentication middleware is registered before the router is mounted
- Register an error-handling middleware after the routes, so an authorization error thrown by the guard is rendered as 403 rather than 500
- For object-level findings, scope the lookup by the authenticated user so a record belonging to someone else cannot be returned at all
- Test with tokens representing different roles: 403 where a role or permission is the gate, and - for a guessable resource id - the same 404 an unknown id returns, matching body as well as status
- Apply `express-rate-limit` to sensitive routes to slow enumeration of authorization gaps, setting Express's `trust proxy` correctly first, or every client behind the proxy shares one rate-limit key
