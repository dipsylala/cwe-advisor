# CWE-863: Incorrect Authorization - C#

## LLM Guidance

In ASP.NET Core, Incorrect Authorization usually shows up as an `[Authorize(Roles = "...")]` or hand-written `if` check that validates the wrong thing: a denylist role comparison (`if (user.Role != "Admin")`) that fails open on new roles, or a check that confirms a resource exists without confirming the current user owns it. The fix is to replace ad hoc role comparisons with policy-based authorization and to add resource-based authorization (`IAuthorizationHandler`) so ownership is checked alongside resource type, not instead of it.

## Key Principles

- Replace inline role-string comparisons with named policies (`services.AddAuthorization(options => options.AddPolicy(...))`) evaluated by the framework, not by hand-rolled `if`/`!=` logic
- Never use a denylist comparison (`role != "Admin"`) to gate access - enumerate the allowed roles or permissions explicitly
- For per-resource checks, use resource-based authorization (`IAuthorizationHandler<TRequirement, TResource>`) so ownership is validated against the authenticated `ClaimsPrincipal`, never against a client-supplied user ID or role claim in the request body
- Look up the resource owner/tenant from the database inside the handler; do not trust an `OwnerId` field submitted by the client
- Call `IAuthorizationService.AuthorizeAsync` on every controller action that reads or mutates the resource, including PUT/PATCH/DELETE variants, not only the initial GET
- Have handlers call `context.Fail()` or simply not call `context.Succeed()` on any code path that does not explicitly match - unhandled cases must deny

## Taint Sinks

`user.IsInRole()`, `[Authorize(Roles = "...")]` role-only attributes, inline `role != "Admin"` checks, controller actions without `IAuthorizationService.AuthorizeAsync()`

## Remediation Steps

- Locate - Find role or permission checks using string comparison (`user.IsInRole(...)`, `role != "Admin"`, custom `if` blocks) and any resource lookups that never check an owner/tenant field
- Trace data flow - Confirm which claim or field the check reads (`User.FindFirstValue(...)` vs. a request-body role/ownerId field) and which actions skip the check
- Replace the unsafe pattern - Convert denylist role comparisons to `[Authorize(Policy = "...")]` policies with explicit allowed-role or claim requirements
- Bind, encode, validate, or authorize - Implement `AuthorizationHandler<TRequirement, TResource>` that loads the resource server-side and compares its owner ID to `User.FindFirstValue(ClaimTypes.NameIdentifier)`, and register it with `services.AddScoped<IAuthorizationHandler, ...>()`
- Break taint after allowlist validation - Resolve the caller's role/permission from the validated `ClaimsPrincipal`, not from any client-supplied field, before making the decision
- Harden configuration - Add a global fallback policy (`options.FallbackPolicy = ...RequireAuthenticatedUser().Build()`) so unattributed endpoints do not default to anonymous access
- Test - Add tests for an authenticated non-owner requesting another user's resource, and for a role value the allowlist does not recognize, confirming both are denied
