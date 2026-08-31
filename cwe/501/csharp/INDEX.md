# CWE-501: Trust Boundary Violation - C#

## LLM Guidance

The reported line is usually `HttpContext.Session.SetString(...)` holding a request value, but the
higher-value case in ASP.NET Core is a **claim**: a `Claim` constructed from request data and added to
the `ClaimsIdentity` is read afterwards by `[Authorize(Roles = ...)]` and by every policy handler,
which is the most trusted store the framework has. Validate and authorize at the write, and prefer
storing a server-resolved identifier over the submitted value.

## Key Principles

- Never build a `Claim` - especially `ClaimTypes.Role`, `ClaimTypes.NameIdentifier`, or a tenant claim
  - from request data. The authentication cookie is protected by Data Protection, so it is signed and
  encrypted, but that proves the *server issued* the claim, not that its value was ever checked. A
  bad value laundered through the cookie is trusted more afterwards, not less
- Validate and authorize at the `Session.Set*` call. Session data in ASP.NET Core is held server-side
  with only the session id in the cookie, so the risk is not tampering in transit - it is that later
  readers treat the value as established fact
- Call `SignInAsync` again after any trust-level change so the principal is reissued, and treat a
  long-lived cookie carrying a stale claim as part of this finding: a role revoked in the database is
  still present in an issued cookie until it expires or the security stamp is validated
- ASP.NET Core Identity's security stamp is the mechanism for that - `SecurityStampValidatorOptions`'s
  `ValidationInterval` (configured via `services.Configure<SecurityStampValidatorOptions>(o => ...)`,
  30 minutes by default) controls how often a principal is revalidated, and lengthening it widens the
  window in which a revoked authority still works
- `CookieTempDataProvider` is the framework default rather than a template choice, so `TempData` puts
  the value on the client unless `AddSessionStateTempDataProvider()` is registered. It is encrypted
  with `IDataProtector`, so the user cannot read or forge it; the reason to keep a trust decision out
  of it is that it is chunked under a 4096-byte cookie limit and its lifetime belongs to the client
- Store the resolved value rather than the submitted one: keep a user or tenant id in the session and
  load the role on use, rather than caching a role string that an authorization check will believe
- `HttpContext.Items` is per-request and is a reasonable place for a validated value, but a middleware
  that writes request data there and a later component that trusts it is the same weakness at a
  shorter timescale
- Session values are byte arrays or strings; a complex object round-tripped through JSON into session
  is deserialized on read, so an attacker-influenced graph there is a deserialization concern
  (CWE-502) reached through this one

## Taint Sinks

`HttpContext.Session.SetString()`, `Session.Set()`, `Session.SetInt32()`, `new Claim(...)` added to a
`ClaimsIdentity`, `ClaimsPrincipal.AddIdentity()`, `HttpContext.Items[...]`, `TempData[...]`,
`AuthenticationProperties.Items`

## Remediation Steps

- Locate - find `Session.Set*` calls and `Claim` construction whose value comes from `Request.Form`,
  `Request.Query`, a route value, a header, or a bound model
- Trace data flow - follow the stored value to its readers, and mark every authorization attribute or
  policy handler that consumes it; those are what the fix protects
- Identify the unsafe pattern - a raw request value in session, a claim built from input, or a role
  string cached rather than resolved
- Replace the unsafe pattern - validate and authorize immediately before the write, and store a
  server-resolved identifier, loading the role or permission from the data store on use
- Bind, encode, validate, or authorize - resolve claims from the authenticated user record at sign-in,
  never from the request that triggered it
- Harden configuration - reissue the principal with `SignInAsync` on a trust-level change, keep the
  security stamp validation interval short enough that revocation takes effect, and move anything
  sensitive out of cookie-backed `TempData`
- Test - submit a modified role or tenant parameter and confirm it never reaches a claim or the
  session, and verify that revoking a role in the database stops authorizing within the expected
  interval rather than at cookie expiry
