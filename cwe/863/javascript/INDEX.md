# CWE-863: Incorrect Authorization - JavaScript

## LLM Guidance

In Express and similar Node.js frameworks, Incorrect Authorization commonly appears as middleware that trusts a role or user ID sent by the client (`req.body.role`, a decoded-but-unverified JWT claim, or a hidden form field) instead of resolving it server-side, or as an inline role comparison (`if (user.role !== 'admin')`) standing in for a shared check - note that this shape denies every unrecognised role, so the fail-open variant is the one that enumerates the roles to reject. Another frequent variant is a check applied only to one route (`GET /orders/:id`) but forgotten on a sibling route (`PATCH /orders/:id`). Fix by re-validating role and ownership from a trusted server-side source on every route, using an allowlist for role comparisons.

## Key Principles

- Never trust `req.body`, `req.query`, or unverified token claims for the acting user's role or ID; resolve identity from the verified session or a signature-checked JWT (`jsonwebtoken.verify`, not `jwt.decode`, which "will not verify whether the signature is valid"). Confirm what sets the property you then trust - Express defines no `req.user`, and express-jwt has used `req.auth` since v7
- Pin `jsonwebtoken` at 9.0.0 or later and pass an explicit `algorithms` list. On 8.5.1 and earlier `verify()` itself could be bypassed by defaulting to the `none` algorithm (CVE-2022-23540), and a key-retrieval flaw allowed a token signed with an RSA public key to verify as HMAC (CVE-2022-23541), so "use verify" is not sufficient guidance without the floor
- Use an allowlist of permitted roles (`const allowedRoles = ['admin', 'editor']; if (!allowedRoles.includes(role))`) rather than a chain of inline comparisons. `includes` compares by strict equality, so confirm `role` is a string first - a parsed query string or JSON body can deliver an array or object, which matches nothing and may skip a branch the code expected to take
- Add ownership checks alongside role checks: a role proves what kind of caller this is, never which records are theirs. Scope the query by the authenticated user, or load the resource and compare its `ownerId` to the user id resolved server-side
- Apply the same authorization middleware to every route for a resource, including PUT/PATCH/DELETE and any bulk-action endpoints, rather than repeating inline checks that can drift
- Re-validate authorization on the server for every request; a check performed only in client-side JavaScript or hidden UI elements is not a control
- Default to `403 Forbidden` when the role is unrecognized or an error occurs while resolving the decision, and to 401 only when credentials are missing, expired or invalid - a 401 must carry a `WWW-Authenticate` header. Where the failure is ownership of a guessable id, answer with the same 404 an unknown id returns, matching body as well as status

## Taint Sinks

`req.body`, `req.query`, `req.user`, `jwt.decode()`, `jwt.verify()`, `Array.prototype.includes()`, `router.use()`

## Remediation Steps

- Locate - Find middleware or route handlers reading role/user data from `req.body`, `req.query`, or a decoded-without-verification token, and any inline role comparisons standing in for a shared check
- Trace data flow - Identify which routes for the same resource include the check and which sibling routes (other HTTP methods, bulk endpoints) omit it
- Replace the unsafe pattern - Convert `role !== 'admin'` checks to an allowlist array lookup, and move role resolution to server-verified session/token data
- Bind, encode, validate, or authorize - Scope the query by the authenticated user, or where that is impractical load the resource and compare its owner field to the server-resolved user id
- Break taint after allowlist validation - Store the verified role/user ID from the session or verified token in `req.user`, and use only that object in authorization decisions, never the raw request body
- Harden configuration - Extract the check into shared middleware applied to every route for the resource so new routes cannot be added without it
- Test - Add supertest/integration tests for a non-owner with a valid session, an unrecognized role value, and each HTTP method on the route. Expect 403 for the unrecognised role and, for the non-owner, the same 404 an unknown id produces
