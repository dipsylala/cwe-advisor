# CWE-862: Missing Authorization - C#

## LLM Guidance

In ASP.NET Core, Missing Authorization typically appears as a controller action or Minimal API endpoint carrying only `[Authorize]` with no `Roles`, `Policy`, or resource-based check, or as a new endpoint added without any `[Authorize]` attribute while sibling endpoints are protected. Fix by adding policy-based authorization (`[Authorize(Policy = "...")]`) for role/claim checks, and `IAuthorizationService.AuthorizeAsync` for resource-based checks where the decision depends on the specific entity being accessed, such as record ownership.

## Key Principles

- `[Authorize]` alone only confirms authentication; add `Roles`, `Policy`, or a resource-based check for authorization
- Define authorization policies centrally in `Program.cs` via `AddAuthorization` so new endpoints opt into a named policy rather than inheriting implicit access
- Use `IAuthorizationService.AuthorizeAsync(User, resource, policyName)` for resource-based checks, such as verifying the current user owns the record being fetched or modified, not just a role check
- Set a global fallback policy (`options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()`) so unattributed endpoints require at least authentication by default
- Do not rely on hiding UI controls or client-side route guards; every check must run server-side
- Cover Minimal API endpoints (`app.MapGet(...)`) the same way as MVC controllers; `[Authorize]` on a controller does not extend to a separately registered Minimal API route
- `.RequireAuthorization(...)` on the endpoint (or a `FallbackPolicy`) puts the check in the routing table rather than in the handler, so a new endpoint inherits it
- `AuthorizeView` hides UI and enforces nothing - the server-side check must exist independently, since the API is reachable without the component

## Taint Sinks

`[HttpGet]`, `[HttpPost]`, `[HttpPut]`, `[HttpDelete]` actions, `app.MapGet()`, `app.MapPost()` routes, SignalR `Hub` methods lacking `[Authorize]`/`AuthorizeAsync()`

## Remediation Steps

- Locate - Identify controller actions, Minimal API route handlers, and SignalR hubs that perform sensitive operations or return sensitive data
- Check for missing checks - Confirm the action has no `[Authorize]` attribute, has `[Authorize]` without a `Roles`/`Policy` value, or has no resource-based ownership check despite operating on a specific record
- Add role/claim authorization - Apply `[Authorize(Roles = "Admin")]` or `[Authorize(Policy = "CanManageOrders")]` for actions gated by role or claim
- Add resource-based authorization - Call `IAuthorizationService.AuthorizeAsync` with an `IAuthorizationHandler` that loads the resource and compares it to the authenticated `ClaimsPrincipal` before returning or mutating a specific entity; derive it from `AuthorizationHandler<TRequirement, TResource>`, call `context.Succeed(requirement)` only on a match, register it with `AddScoped<IAuthorizationHandler, ...>()`, and return `Forbid()` when the result is not `Succeeded`
- Register policies centrally - Define policies in `AddAuthorization` in `Program.cs` and set a `FallbackPolicy` so new endpoints require authentication by default
- Harden configuration - Ensure `app.UseAuthorization()` is registered after `app.UseAuthentication()` and before endpoint mapping
- Test - Write integration tests that call each endpoint as an authenticated user without the required role or policy and assert 403, and as a user who owns a different entity and assert the 404 a lookup scoped by owner returns
