# CWE-501: Trust Boundary Violation - JavaScript

## LLM Guidance

The reported line is `req.session.role = req.body.role`, or a bulk copy such as
`Object.assign(req.session, req.body)`. The session is the trusted store: later middleware and route
handlers read it and act on it because it came from the session rather than the request. The two
things worth establishing first are which session store is in use - `express-session` keeps data
server-side, `cookie-session` keeps it in the client cookie - and whether the application's real
trusted store is actually a JWT, where the same weakness appears at issue time.

## Key Principles

- Validate and authorize at the write. Every later reader is entitled to skip the check, and a bulk
  copy (`Object.assign`, spread, or a `for...in` over `req.body`) writes keys nobody enumerated -
  including ones added to the request specifically because they are never validated
- Know which store you have. `express-session` holds data server-side keyed by the cookie, so a bad
  write is a privilege problem. `cookie-session` serialises the object into the cookie, so the same
  write also discloses it to the user, and the object is size-limited
- A JWT is the same weakness with a signature on it: a claim built from `req.body` at login is
  verified on every later request, and `jwt.verify()` succeeding proves the token was issued by this
  server - not that the claim was ever checked. Derive claims from the authenticated user record, not
  from the request that logged them in
- Call `req.session.regenerate()` on any trust-level change, and note it replaces the session object,
  so values set before the call are lost unless copied across afterwards - a fix that regenerates in
  the wrong order silently drops the very authority it just established
- Store a resolved identifier and load the authority on use: keep a user id in the session and look up
  the role, rather than caching a role string that an authorization middleware will believe
- `req.user` set by Passport or a custom middleware is the trusted store for everything downstream;
  never merge request fields into it, and be specific about what the deserialization callback puts
  there
- Prototype-pollution keys are a live concern for any bulk copy into a persistent object: reject
  `__proto__`, `constructor` and `prototype` before merging, or build the target with
  `Object.create(null)` - which is CWE-1321 reached through this weakness
- `res.locals` is per-request and fine for a validated value, but a template or later middleware
  cannot tell whether what it finds there was checked, so the same naming discipline applies

## Taint Sinks

`req.session.<prop> =`, `Object.assign(req.session, ...)`, spread into `req.session`,
`req.session.user = req.body`, `jwt.sign()` with request-derived claims, `req.user` assignment in
middleware, `res.locals` assignment from request data, `app.locals`

## Remediation Steps

- Locate - find assignments into `req.session`, `req.user`, `res.locals` or `app.locals` whose value
  comes from `req.body`, `req.query`, `req.params`, a header or a cookie, plus any `jwt.sign()` call
- Establish the store - `express-session` versus `cookie-session` versus a JWT - since that decides
  whether the write also discloses the value and whether it is size-limited
- Trace data flow - follow the key to its readers and mark the middleware and handlers that make an
  authorization decision on it
- Identify the unsafe pattern - a raw request value written into the session, a bulk copy of the
  request body, or a JWT claim built from input at login
- Replace the unsafe pattern - validate and authorize immediately before the write, assign named
  fields rather than merging objects, and store a resolved identifier with the authority loaded on use
- Bind, encode, validate, or authorize - build JWT claims from the user record retrieved during
  authentication, never from the login request body
- Harden configuration - call `req.session.regenerate()` on a trust-level change and re-apply the new
  values after it, and reject prototype keys before any merge into a persistent object
- Test - submit an extra `role` or `isAdmin` field in the login body and confirm it reaches neither
  the session nor a token claim, and decode an issued JWT to confirm its claims match the database
