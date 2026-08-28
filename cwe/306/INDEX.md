# CWE-306: Missing Authentication for Critical Function

## LLM Guidance

Missing authentication occurs when a critical function, route, or handler has no identity check at all - not a flawed one. The usual cause is a path missed when authentication was wired up elsewhere: an internal admin API left open because "it's not linked from the UI," a debug endpoint shipped without auth, a new route that never inherited the shared auth middleware, or a service-to-service API that trusts network location instead of verifying caller identity. This differs from CWE-287 (auth logic exists but is bypassable), CWE-862 (identity is verified but the permission is never checked), and CWE-863 (a permission check exists but its logic is wrong) - CWE-306 has no identity check whatsoever. Remediate by enumerating every code path that reaches the sensitive function and confirming each one requires authentication.

## Key Principles

- Every critical function - state change, non-public data read, admin action, internal API - must require verified caller identity before executing
- Do not rely on obscurity (undocumented URL, no UI link), network placement (internal network, service mesh), or client-side checks as a substitute for server-side authentication
- Enforce authentication centrally (middleware, gateway, framework guard) and apply it by default, not as a per-route opt-in
- New routes, handlers, and service endpoints must inherit the same authentication requirement as sibling endpoints unless intentionally public
- Fail closed - if an authentication check cannot run or its configuration is missing, deny access rather than default to allow
- Service-to-service calls must verify caller identity (mTLS, signed tokens, service credentials), not just trust that the request originated internally
- Make authentication the default for the router rather than a per-route opt-in, then enumerate the routes and confirm each one: the handler is usually correct and the defect lives in the routing table, where a route registered outside the shared middleware group silently gets nothing and a diff shows nothing wrong
- Authenticating at the gateway only leaves every backend reachable directly - another internal service, a misconfigured route, a debug port - trusting the request implicitly; each service verifies identity itself
- An unlinked admin or debug route is not protected: test the endpoint directly rather than through the UI, since that is the path an attacker uses
- Route by which check is missing: identity never established is this entry, a permission check missing after identity is CWE-862, and a permission check with wrong logic is CWE-863

## Remediation Steps

- Locate - Enumerate all routes, RPC methods, message handlers, and internal APIs, including debug, health-check, and internal-only endpoints
- Diff against coverage - Compare that list against what the authentication middleware, gateway, or framework guard actually covers; treat anything not on the covered list as a candidate gap
- Classify sensitivity - For each uncovered path, determine whether it performs a critical function (data access, state change, admin capability, trust-boundary crossing); intentionally public endpoints are out of scope
- Confirm root cause - Determine why the path lacks authentication: never registered under shared middleware, added outside the standard routing group, or trusting network location instead of identity
- Apply the fix - Attach the same authentication mechanism used elsewhere (session check, token validation, service credential verification), preferring a default-applied guard over a per-route opt-in
- Fail closed - Ensure the check denies access when misconfigured or when identity cannot be established, rather than allowing the request through
- Test directly against the endpoint - Send unauthenticated requests straight to the route or handler, not just through the UI, and confirm the response is a rejection
- Regression-check sibling routes - Verify the fix did not exempt other paths registered the same way, and add the endpoint to any route inventory used to catch future gaps
