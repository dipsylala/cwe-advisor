# CWE-862: Missing Authorization - C#

## LLM Guidance

In ASP.NET Core, Missing Authorization typically appears as a controller action or Minimal API endpoint carrying only `[Authorize]` with no `Roles`, `Policy`, or resource-based check, or as a new endpoint added without any `[Authorize]` attribute while sibling endpoints are protected. Fix by adding policy-based authorization (`[Authorize(Policy = "...")]`) for role/claim checks, and `IAuthorizationService.AuthorizeAsync` for resource-based checks where the decision depends on the specific entity being accessed, such as record ownership.

## Key Principles

- `[Authorize]` alone only confirms authentication; add `Roles`, `Policy`, or a resource-based check for authorization
- Define authorization policies centrally in `Program.cs` via `AddAuthorization` so new endpoints opt into a named policy rather than inheriting implicit access
- Use `IAuthorizationService.AuthorizeAsync(User, resource, policyName)` for resource-based checks, such as verifying the current user owns the record being fetched or modified, not just a role check
- Set a global fallback policy (`options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()`, ASP.NET Core 3.0+) so endpoints carrying no authorization metadata require authentication by default. It will not tighten the endpoint this entry is about: an action with a bare `[Authorize]` is evaluated against `DefaultPolicy` instead, and `[AllowAnonymous]` opts out
- Do not rely on hiding UI controls or client-side route guards; every check must run server-side
- Cover Minimal API endpoints (`app.MapGet(...)`) the same way as MVC controllers; authorization is computed per endpoint from its own metadata, so `[Authorize]` on a controller does not reach a separately registered Minimal API route
- A SignalR hub authorizes at connection time and caches the principal for the connection's lifetime, so a role revoked mid-session keeps working on hub methods until the client reconnects; a failed hub-method check returns an error to the caller rather than an HTTP status
- `.RequireAuthorization(...)` attaches the check as endpoint metadata rather than handler code, but it applies only to the endpoint it is called on. For a rule a later endpoint inherits, call it on a route group (`app.MapGroup("/orders").RequireAuthorization(...)`) or rely on the `FallbackPolicy`
- `AuthorizeView` decides what renders, not what may execute: it "doesn't enforce security on the event handler itself", so a handler reachable only from an authorized button is still invokable. Add the check inside the handler or the API it calls. In client-side Blazor the rendered markup is not a control at all, since the code can be modified by the user

## Taint Sinks

`[HttpGet]`, `[HttpPost]`, `[HttpPut]`, `[HttpDelete]` actions, `app.MapGet()`, `app.MapPost()`, `MapHub()` registrations, `[Authorize]`, `.RequireAuthorization()`, `IAuthorizationService.AuthorizeAsync()`

## Remediation Steps

- Locate - Identify controller actions, Minimal API route handlers, and SignalR hubs that perform sensitive operations or return sensitive data
- Check for missing checks - Confirm the action has no `[Authorize]` attribute, has `[Authorize]` without a `Roles`/`Policy` value, or has no resource-based ownership check despite operating on a specific record
- Add role/claim authorization - Apply `[Authorize(Roles = "Admin")]` or `[Authorize(Policy = "CanManageOrders")]` for actions gated by role or claim
- Add resource-based authorization - Call `IAuthorizationService.AuthorizeAsync` with an `IAuthorizationHandler` that loads the resource and compares it to the authenticated `ClaimsPrincipal` before returning or mutating a specific entity; derive it from `AuthorizationHandler<TRequirement, TResource>`, call `context.Succeed(requirement)` only on a match, register it with `AddSingleton<IAuthorizationHandler, ...>()` - `AddScoped` only where the handler resolves EF Core or Identity services - and return `Forbid()` for an authenticated caller, `Challenge()` for an unauthenticated one
- Register policies centrally - Define policies in `AddAuthorization` in `Program.cs` and set a `FallbackPolicy` so new endpoints require authentication by default
- Harden configuration - On .NET 7+, `WebApplication` registers the authentication and authorization middleware automatically once `AddAuthentication`/`AddAuthorization` are called, so a missing `app.UseAuthorization()` is usually not the defect. Call both explicitly only to control ordering - `UseCors` must precede them - and then keep authorization after authentication
- Audit coverage mechanically - Enumerate the application's endpoints through `EndpointDataSource` in the test host and assert each one carries either an authorization policy or an explicit `[AllowAnonymous]`, so a route added later cannot silently miss the check
- Test - Write integration tests that call each endpoint as an authenticated user without the required role or policy, and as a user who owns a different entity, asserting the 403 and the owner-scoped 404 respectively. Assert against the status the app actually returns: under cookie authentication a forbid is converted to a redirect to the access-denied path, not a 403, except on the known API endpoints (`[ApiController]`, Minimal APIs, SignalR) that return status codes from .NET 10 onward
