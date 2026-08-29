# CWE-285: Improper Authorization - C#

## LLM Guidance

In ASP.NET Core, `[Authorize]` and `[AllowAnonymous]` attributes only establish whether a request is authenticated - they do not verify that the authenticated user has permission to access the specific resource identified in the request. An action that reads an `id` from the route or body and loads or modifies that record without checking the caller's ownership or permission for that specific resource is vulnerable to broken object-level authorization (BOLA/IDOR), even though `[Authorize]` is present and authentication succeeds. Add an explicit per-resource check - via ASP.NET Core's `IAuthorizationService` (resource-based policies) or an equivalent ownership lookup - before performing the operation.

## Key Principles

- Treat `[Authorize]` as necessary but not sufficient: it confirms identity, not permission for the specific resource being requested
- Explicitly verify the authenticated user owns or is granted access to the specific resource/id in the request before reading or modifying it
- Perform the resource-level check server-side, inside the action, for every request that takes a route- or body-supplied identifier
- Use `IAuthorizationService` with resource-based policies (`AuthorizationHandler<TRequirement, TResource>`) for centralized, reusable per-resource checks
- Never assume a client-supplied id is safe to act on solely because the caller is authenticated or holds a given role
- Combine `[Authorize(Roles = "...")]` for coarse-grained gating with resource-level checks for fine-grained, per-record access control
- Set an authorization `FallbackPolicy` requiring an authenticated user, so an endpoint carrying no authorization metadata at all is denied by default rather than left open by a forgotten `[Authorize]`; make `[AllowAnonymous]`/`.AllowAnonymous()` the deliberate exception. Note its limit: an endpoint with a bare `[Authorize]` is evaluated against `DefaultPolicy` instead, so the fallback does not tighten the resource-level gap this entry is about
- `UseAuthentication()` must be registered before `UseAuthorization()` in the pipeline; reversed, the authorization middleware runs against an unauthenticated principal. On .NET 7+ `WebApplication` adds both automatically once the services are registered, so call them explicitly only to place them relative to other middleware such as `UseCors`
- `[Authorize]` alone proves only that the caller is authenticated - use `[Authorize(Policy = "...")]` for a permission and check resource ownership separately, since a policy cannot see which record is being requested
- Take the user identity from the validated principal rather than from a route or body parameter. `ClaimTypes.NameIdentifier` holds it only while inbound claim mapping is on - `MapInboundClaims = false`, or a cleared `JsonWebTokenHandler.DefaultInboundClaimTypeMap` (`JwtSecurityTokenHandler` before ASP.NET Core 8), leaves the raw `sub` - so `UserManager.GetUserId(User)` is the mapping-independent form

## Taint Sinks

`[Authorize]`, `[AllowAnonymous]`, `IAuthorizationService.AuthorizeAsync()`, `AuthorizationHandler<TRequirement, TResource>`, `User.FindFirstValue()`, `DbSet.Find()`, `FirstOrDefaultAsync()`

## Remediation Steps

- Identify actions that accept a route- or body-supplied resource id and confirm `[Authorize]` is present (necessary, not sufficient)
- Add an explicit resource-level check before reading or modifying the record - call `IAuthorizationService.AuthorizeAsync()` with a resource-based policy, or a service method that verifies the caller owns or has access to that specific id
- Return `Forbid()` for an authenticated caller and `Challenge()` for an unauthenticated one. Check what the scheme in use actually emits: under cookie authentication a forbid becomes a redirect to the access-denied path rather than a 403, except on the known API endpoints (`[ApiController]`, Minimal APIs, SignalR) that return status codes from .NET 10. Where the identifier is guessable, prefer scoping the lookup by owner and answering 404 for both the missing and the not-owned case, so the response does not confirm the record exists
- Apply role-based authorization (`[Authorize(Roles = "Admin")]`) for endpoints that are privileged regardless of resource ownership
- Use policy-based authorization for complex, multi-condition access rules
- Test each endpoint as an authenticated but unauthorized user (e.g. a different owner's id) to confirm the resource-level check blocks access, not just an anonymous request
