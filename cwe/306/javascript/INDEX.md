# CWE-306: Missing Authentication for Critical Function - JavaScript

## LLM Guidance

In Express, middleware protects only the routes registered after it, so `app.use(requireAuth)` placed below a route definition leaves that route anonymous while looking correct in review. The defect is therefore in registration order and router mounting rather than in the handler, and it is invisible in a diff that adds a single route. Fix by mounting authentication on the router that carries the protected routes, and confirming every entry point - HTTP routes, GraphQL resolvers, sockets, and framework-specific handlers - is behind it.

## Key Principles

- Registration order is the control in Express: middleware added with `app.use()` applies only to routes registered after that call, so a route defined earlier in the file is public no matter how the middleware is written
- Mount authentication on the `express.Router()` that holds the protected routes rather than on `app`, so a route added to that router inherits it and a route added elsewhere is visibly on a different router
- In Next.js, `middleware.ts` runs only for paths its `matcher` config selects - route handlers, server actions, and API routes outside the matcher receive nothing. Server actions are ordinary POST endpoints reachable directly, not only through the form that renders them
- A GraphQL server usually authenticates the single HTTP route, which says nothing about individual resolvers; each field is its own entry point, so a resolver reachable through an unauthenticated query is the gap
- Socket.IO authenticates the handshake through `io.use()`; once connected, every `socket.on()` handler runs without a further check, so an event that performs a critical function needs its own verification
- Health, metrics, and debug routes are commonly registered near the top of the file, which in Express means before the auth middleware - treat their position as part of the finding
- Verify the token rather than decoding it: `jwt.decode()` returns the payload without checking the signature, so code that reads a user id from it has established no identity at all

## Taint Sinks

`app.get()`/`app.post()` registered before `app.use(requireAuth)`, routers mounted with `app.use(path, router)` without the shared middleware, Next.js route handlers and server actions outside the `middleware.ts` `matcher`, GraphQL resolvers, `socket.on()` handlers, `jwt.decode()` used in place of `jwt.verify()`

## Remediation Steps

- Locate - Enumerate every entry point: Express route definitions, mounted routers, Next.js route handlers and server actions, GraphQL resolvers, and Socket.IO event handlers
- Diff against coverage - For each Express route, determine whether the auth middleware was registered before it, and for each router whether the middleware is on that router or only on a sibling
- Confirm identity is never established - A route that authenticates but omits a role or ownership check is CWE-862; a route that decodes a token without verifying it belongs here, since no identity is proven
- Apply the fix - Attach the authentication middleware to the router carrying the protected routes, above every route definition on it, and move any route registered before it
- Cover the non-HTTP entry points - Add resolver-level checks in GraphQL and per-event checks in Socket.IO handlers that perform critical functions
- Reposition infrastructure routes - Move health, metrics, and debug endpoints behind the middleware, or confirm each is intentionally public
- Test directly against the endpoint - Call each route with `curl` and no credentials rather than exercising the UI, and confirm a 401 rather than a 200
