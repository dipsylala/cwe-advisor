# CWE-306: Missing Authentication for Critical Function - Go

## LLM Guidance

Go has no framework-level default, so authentication is whatever wrapping the route registration happens to have: `mux.Handle("/admin", authMiddleware(handler))` is protected and `mux.Handle("/admin", handler)` is not, and the difference is one call in a line that otherwise reads normally. The routing table is therefore where the defect lives, not the handler. Fix by grouping protected routes so the wrapper is applied once, and by serving an explicitly constructed mux rather than the package-level default.

## Key Principles

- Serve an explicitly constructed `http.ServeMux` and never pass `nil` to `http.ListenAndServe`, which serves `http.DefaultServeMux` - a global that any package in the build can register on
- Importing `net/http/pprof` for its side effect registers `/debug/pprof/*` on `DefaultServeMux`, and `expvar` registers `/debug/vars` the same way. Serving the default mux therefore publishes profiling and heap data through handlers nobody in the project wrote; if profiling is needed, register those handlers deliberately on a separate, authenticated, non-public listener
- Wrap once at the group rather than per route: with `chi`, put protected routes inside `r.Group(func(r chi.Router) { r.Use(auth); ... })` so a route added to that block inherits the check and a route added outside it is visibly outside. Registering directly on the parent router is the shape this finding usually takes
- `http.FileServer` and any other handler value needs the same wrapping - a directory served through it is as reachable as a handler function
- gRPC interceptors are configured per server: `grpc.NewServer(grpc.UnaryInterceptor(authInterceptor), grpc.StreamInterceptor(...))`. A service registered on a second `grpc.Server` built without them has no authentication, and both servers can look correct in isolation
- Cover both interceptor kinds - a unary interceptor alone leaves every streaming method unauthenticated
- Establish identity by verifying, not parsing: a JWT library's unverified parse (for example `jwt.ParseUnverified`) returns claims without checking the signature, so a user id read from it proves nothing
- Put the authenticated identity into the request `context.Context` and have handlers read it from there, so a handler that runs without the middleware finds nothing rather than a default value it might trust

## Taint Sinks

`http.ListenAndServe(addr, nil)`, `http.HandleFunc()` registering on `DefaultServeMux`, blank imports of `net/http/pprof` or `expvar`, routes registered outside a middleware-wrapped group, `grpc.NewServer()` with no auth interceptor, `jwt.ParseUnverified`

## Remediation Steps

- Locate - Read the routing table: every `mux.Handle`/`HandleFunc`, router group, and `RegisterXServer` call, plus the argument passed to `ListenAndServe`
- Diff against coverage - Determine which registrations are inside a middleware-wrapped group and which are not; anything registered on the parent router or the default mux is a candidate gap
- Confirm identity is never established - A handler that reads a user from context but never checks role or ownership is CWE-862; a handler that parses a token without verifying it belongs here
- Apply the fix - Move protected routes into the wrapped group, and replace `nil` in `ListenAndServe` with the explicitly built mux
- Account for side-effect imports - Search for blank imports of `net/http/pprof` and `expvar`, and either remove them or bind them to a separate authenticated listener
- Cover gRPC fully - Add both unary and stream interceptors to every `grpc.NewServer` construction in the binary, not just the first
- Test directly against the endpoint - Send unauthenticated requests to each route, including `/debug/pprof/` and `/debug/vars`, and confirm a 401 rather than a 200
