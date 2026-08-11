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

## Taint Sinks

controller actions accepting a route/body `id` (e.g. `GetProfile(int id)`) that call a data-access method (`_repository.Find(id)`, `_service.GetUser(id)`) without a preceding `IAuthorizationService.AuthorizeAsync()` or ownership check, `[Authorize]` alone treated as sufficient for resource-level access

## Remediation Steps

- Identify actions that accept a route- or body-supplied resource id and confirm `[Authorize]` is present (necessary, not sufficient)
- Add an explicit resource-level check before reading or modifying the record - call `IAuthorizationService.AuthorizeAsync()` with a resource-based policy, or a service method that verifies the caller owns or has access to that specific id
- Return `Forbid()` (403) when the resource check fails, distinct from the 401 an unauthenticated request receives
- Apply role-based authorization (`[Authorize(Roles = "Admin")]`) for endpoints that are privileged regardless of resource ownership
- Use policy-based authorization for complex, multi-condition access rules
- Test each endpoint as an authenticated but unauthorized user (e.g. a different owner's id) to confirm the resource-level check blocks access, not just an anonymous request

## Safe Pattern

```csharp
[Authorize]  // Protect all actions by default
[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    [AllowAnonymous]  // Explicitly allow public access
    [HttpGet("public")]
    public IActionResult GetPublicInfo() => Ok("Public data");
    
    [HttpGet("profile/{id}")]  // Requires authentication and resource authorization
    public IActionResult GetProfile(int id)
    {
        if (!_authorizationService.CanViewUser(User, id))
            return Forbid();
        return Ok(_userService.GetUser(id));
    }
    
    [Authorize(Roles = "Admin")]  // Requires admin role
    [HttpDelete("{id}")]
    public IActionResult DeleteUser(int id) => NoContent();
}
```
