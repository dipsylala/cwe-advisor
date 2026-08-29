# CWE-285: Improper Authorization - C#

## LLM Guidance

In ASP.NET Core, `[Authorize]` and `[AllowAnonymous]` establish only whether a request is authenticated - they do not verify that the authenticated user may act on the specific resource named in the request. An action that reads an `id` from the route or body and loads or modifies that record without checking the caller's ownership is vulnerable to broken object-level authorization (BOLA/IDOR) even though `[Authorize]` is present. Microsoft's own reason is worth carrying: attribute evaluation happens before data binding and before the action loads the resource, so the check has to be imperative - `IAuthorizationService.AuthorizeAsync()` inside the action, or a lookup scoped by owner.

## Key Principles

- Treat `[Authorize]` as necessary but not sufficient: combine `[Authorize(Roles = "...")]` or a policy for coarse gating with a resource-level check for per-record access, since a policy cannot see which record is being requested
- `[AllowAnonymous]` wins wherever it is declared, so a class-level one silently disables every method-level `[Authorize]` in that controller - the authorization middleware skips failure handling entirely for an endpoint carrying `IAllowAnonymous` metadata. Audit for its presence, not only for a missing `[Authorize]`
- A resource-based check needs three registrations the prescribed code will not work without: the handler (`AuthorizationHandler<TRequirement, TResource>`, an abstract base class), the policy naming its requirement, and an injected `IAuthorizationService`. Register a handler that touches `DbContext` or `UserManager` with `AddScoped` rather than the `AddSingleton` most samples show, or it captures a scoped dependency
- A handler denies by calling `context.Fail()`. Declining to call `context.Succeed()` is not a denial - every handler for that requirement still runs, and any one of them succeeding authorizes the call
- Set an authorization `FallbackPolicy` requiring an authenticated user, so an endpoint carrying no authorization metadata at all is denied by default rather than left open by a forgotten `[Authorize]`; make `[AllowAnonymous]`/`.AllowAnonymous()` the deliberate exception. Note its limit: an endpoint with a bare `[Authorize]` is evaluated against `DefaultPolicy` instead, so the fallback does not tighten the resource-level gap this entry is about
- `UseAuthentication()` must be registered before `UseAuthorization()`; reversed, the authorization middleware runs against an unauthenticated principal. On .NET 7+ `WebApplication` adds both automatically once it detects `IAuthenticationSchemeProvider` and `IAuthorizationHandlerProvider` in the service provider, placing them immediately after `UseRouting()`, so call them explicitly only to position them against other middleware such as `UseCors`
- Take the user identity from the validated principal rather than from a route or body parameter, and read the claim type the configured scheme actually issues. `ClaimTypes.NameIdentifier` holds it only while inbound claim mapping is on - `MapInboundClaims = false`, which Microsoft's own bearer sample sets, or a cleared `JsonWebTokenHandler.DefaultInboundClaimTypeMap` (`JwtSecurityTokenHandler` before ASP.NET Core 8) leaves the raw `sub`, which is then what to read. `UserManager.GetUserId(User)` is not a way around this: it reads `Options.ClaimsIdentity.UserIdClaimType`, which defaults to the same `ClaimTypes.NameIdentifier`. `FindFirstValue` is itself an extension method from `Microsoft.Extensions.Identity.Core`, not a member of `ClaimsPrincipal`
- `Find()`/`FindAsync()` return an already-tracked entity without querying the database, so an ownership predicate expressed in the query is not evaluated on that path
- Grep the remediation APIs to enumerate what is already protected rather than to find the defect: `[Authorize]`, `IAuthorizationService.AuthorizeAsync()` and `AuthorizationHandler<` all appear in Microsoft's own samples. The finding is an action that binds an id and reaches none of them

## Taint Sinks

`DbSet.Find()`, `DbSet.FindAsync()`, `FirstOrDefaultAsync()`, `SingleOrDefaultAsync()`, `[AllowAnonymous]`, `[FromRoute]`, `[FromBody]`, `context.Succeed()`

## Remediation Steps

- Identify actions that accept a route- or body-supplied resource id and confirm `[Authorize]` is present (necessary, not sufficient)
- Add an explicit resource-level check before reading or modifying the record - inject `IAuthorizationService` and call `AuthorizeAsync()` with a registered resource policy, or scope the lookup query by owner
- Return `Forbid()` for an authenticated caller and `Challenge()` for an unauthenticated one (`Results.Forbid()` in a Minimal API). Check what the scheme emits: under cookie authentication a forbid is a redirect to the access-denied path rather than a 403, except for XHRs, which have always received status codes, and for endpoints carrying `IApiEndpointMetadata` from .NET 10 - `[ApiController]` actions, SignalR, `TypedResults` returns, and minimal API endpoints that read or write JSON. Where the identifier is guessable, prefer scoping the lookup by owner and answering 404 for both the missing and the not-owned case
- Apply role-based authorization (`[Authorize(Roles = "Admin")]`) for endpoints privileged regardless of resource ownership, and policy-based authorization for multi-condition rules
- Test each endpoint as an authenticated but unauthorized user (a different owner's id) to confirm the resource-level check blocks access, not just an anonymous request
