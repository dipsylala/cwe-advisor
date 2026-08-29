# CWE-863: Incorrect Authorization - C#

## LLM Guidance

In ASP.NET Core, Incorrect Authorization usually shows up as a check that validates the wrong thing: an inline role comparison (`if (user.Role != "Admin")`) standing in for a policy, or a check that confirms a resource exists without confirming the current user owns it. The fix is to replace ad hoc role comparisons with policy-based authorization and to add resource-based authorization (`IAuthorizationHandler`) so ownership is checked alongside resource type, not instead of it.

## Key Principles

- Replace inline role-string comparisons with named policies (`services.AddAuthorization(options => options.AddPolicy(...))`) evaluated by the framework, not by hand-rolled `if`/`!=` logic
- Enumerate the allowed roles or permissions explicitly rather than gating on a single inline comparison. Read the shape before labelling it: `role != "Admin"` denies every unrecognised role and so fails closed, while a check that names the roles to reject admits any role added later
- For per-resource checks, derive a handler from the abstract class `AuthorizationHandler<TRequirement, TResource>` - there is no generic `IAuthorizationHandler<,>`; the interface `IAuthorizationHandler` is non-generic and is what you register against. Ownership is then validated against the authenticated `ClaimsPrincipal`, never against a client-supplied user ID or role claim in the request body
- Load the resource in the caller and pass it to `AuthorizeAsync` as the `resource` argument, which is the documented flow and lets the handler stay a singleton; do not trust an `OwnerId` field submitted by the client
- Call `IAuthorizationService.AuthorizeAsync` on every controller action that reads or mutates the resource, including PUT/PATCH/DELETE variants, not only the initial GET
- Handlers for one requirement are OR'd, so declining to call `context.Succeed(requirement)` is not a denial - another handler for the same requirement can still satisfy it. Call `context.Fail()` where the decision must hold regardless of what any other handler concludes

## Taint Sinks

`[Authorize(Roles = "...")]`, `ClaimsPrincipal.IsInRole()`, `User.FindFirstValue()`, `IAuthorizationService.AuthorizeAsync()`, `AuthorizationHandlerContext.Succeed()`

## Remediation Steps

- Locate - Find role or permission checks using string comparison (`user.IsInRole(...)`, `role != "Admin"`, custom `if` blocks) and any resource lookups that never check an owner/tenant field. `IsInRole` is the supported claims-based check and appears in Microsoft's own handler samples, so its presence is not itself the finding - the missing ownership comparison beside it is
- Trace data flow - Confirm which claim or field the check reads (`User.FindFirstValue(...)` vs. a request-body role/ownerId field) and which actions skip the check
- Replace the unsafe pattern - Convert inline role comparisons to `[Authorize(Policy = "...")]` policies with explicit allowed-role or claim requirements
- Bind, encode, validate, or authorize - Implement `AuthorizationHandler<TRequirement, TResource>` that loads the resource server-side and compares its owner ID to the caller's id, and register it with `services.AddSingleton<IAuthorizationHandler, ...>()` - `AddScoped` only where the handler resolves EF Core or Identity services. Do not assume `User.FindFirstValue(ClaimTypes.NameIdentifier)` holds that id: the claim carries it only while inbound claim mapping is on, and `MapInboundClaims = false` per scheme, or clearing `JsonWebTokenHandler.DefaultInboundClaimTypeMap` (`JwtSecurityTokenHandler` before ASP.NET Core 8), leaves the raw `sub` and returns null. `UserManager.GetUserId(User)` is the mapping-independent form
- Break taint after allowlist validation - Resolve the caller's role/permission from the validated `ClaimsPrincipal`, not from any client-supplied field, before making the decision
- Harden configuration - Add a global fallback policy (`options.FallbackPolicy = ...RequireAuthenticatedUser().Build()`, ASP.NET Core 3.0+) so endpoints carrying no authorization metadata do not default to anonymous access. It does not reach the endpoints this entry is about: anything with an `[Authorize]` attribute, even with no policy named, is evaluated against `DefaultPolicy` instead, and `[AllowAnonymous]` opts out entirely
- Test - Add tests for an authenticated non-owner requesting another user's resource, and for a role value the allowlist does not recognize, confirming both are denied
