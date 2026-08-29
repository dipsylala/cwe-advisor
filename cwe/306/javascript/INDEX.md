# CWE-306: Missing Authentication for Critical Function - JavaScript

## LLM Guidance

In Express, middleware protects only the routes registered after it, so `app.use(requireAuth)` placed below a route definition leaves that route anonymous while looking correct in review. The defect is therefore in registration order and router mounting rather than in the handler, and it is invisible in a diff that adds a single route. Fix by mounting authentication on the router that carries the protected routes, and confirming every entry point - HTTP routes, GraphQL resolvers, sockets, and framework-specific handlers - is behind it.

## Key Principles

- Registration order is the control in Express: middleware added with `app.use()` applies only to routes registered after that call, so a route defined earlier in the file is public no matter how the middleware is written
- Mount authentication on the `express.Router()` that holds the protected routes rather than on `app`, so a route added to that router inherits it and a route added elsewhere is visibly on a different router
- Next.js 16 renamed the convention to `proxy.ts` exporting `proxy`; `middleware.ts` is deprecated but still works and remains the only form supporting the edge runtime, so expect either name. With no `matcher` it runs on every request - the exposure is a `matcher` that narrows it, and Next.js recommends the auth pass run on all routes
- Server Functions are POST requests to the route where they are used rather than routes of their own, so a `matcher` that excludes that path skips them silently. Next.js's own instruction is to verify identity inside each action and next to the data access rather than to rely on the proxy
- Treat that check as an optimistic first pass rather than the control: CVE-2025-29927 bypassed authorization done in Next.js middleware through the `x-middleware-subrequest` header. Floors are 15.2.3, 14.2.25, 13.5.9 and 12.3.5, and 11.x has no fixed release
- A GraphQL server usually authenticates the single HTTP route, which says nothing about individual resolvers; each field is its own entry point, so a resolver reachable through an unauthenticated query is the gap
- Socket.IO's `io.use()` runs once per connection, at the handshake; every later `socket.on()` handler runs without a further check, so an event performing a critical function needs its own verification, for which `socket.use()` is the per-packet hook
- Health, metrics, and debug routes are commonly registered near the top of the file, which in Express means before the auth middleware - treat their position as part of the finding
- Verify the token rather than decoding it: `jsonwebtoken`'s `jwt.decode()` returns the payload without checking the signature, so a user id read from it establishes no identity. Its floor is 9.0.0, which closed four advisories in `jwt.verify` itself, CVE-2022-23540's algorithm-confusion bypass among them
- Write a catch-all guard in Express 5 syntax: wildcards must now be named, so `app.use('/*', requireAuth)` throws where `app.use('/{*splat}', requireAuth)` - or a bare `app.use(requireAuth)` above the routes - works

## Taint Sinks

`app.get()`/`app.post()` registered before `app.use(requireAuth)`, routers mounted with `app.use(path, router)` without the shared middleware, Next.js route handlers on paths the `proxy.ts`/`middleware.ts` `matcher` excludes, Server Functions relying on the proxy alone, GraphQL resolvers, `socket.on()` handlers, `jwt.decode()` used in place of `jwt.verify()`

## Remediation Steps

- Locate - Enumerate every entry point: Express route definitions, mounted routers, Next.js route handlers and Server Functions, GraphQL resolvers, and Socket.IO event handlers
- Diff against coverage - For each Express route, determine whether the auth middleware was registered before it, and for each router whether the middleware is on that router or only on a sibling
- Confirm identity is never established - A route that authenticates but omits a role or ownership check is CWE-862; a route that decodes a token without verifying it belongs here, since no identity is proven
- Apply the fix - Attach the authentication middleware to the router carrying the protected routes, above every route definition on it, and move any route registered before it
- Cover the non-HTTP entry points - Add resolver-level checks in GraphQL and per-event checks in Socket.IO handlers that perform critical functions
- Reposition infrastructure routes - Move health, metrics, and debug endpoints behind the middleware, or confirm each is intentionally public
- Test directly against the endpoint - Call each route with `curl` and no credentials rather than exercising the UI, and confirm a 401 rather than a 200
