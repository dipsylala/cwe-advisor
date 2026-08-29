# CWE-306: Missing Authentication for Critical Function - C#

## LLM Guidance

In ASP.NET Core, authentication is opt-in per endpoint: an action with no `[Authorize]`, or a minimal API route with no `.RequireAuthorization()`, is anonymous and nothing reports it. The defect is almost always in the wiring rather than the handler, so read the endpoint registration and the authorization configuration in `Program.cs` before reading the method body. Fix by making authentication the default with a fallback policy, then treating each `[AllowAnonymous]` as a deliberate, reviewable exception.

## Key Principles

- Flip the default rather than adding another attribute: `options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()` in `AddAuthorization` applies to every endpoint that carries no authorization metadata, so a newly added route is protected unless it says otherwise. `DefaultPolicy` does not do this - it only supplies the policy used by a bare `[Authorize]`
- `[AllowAnonymous]` wins over everything, including the fallback policy and an `[Authorize]` on the containing controller, so it is worth searching for on its own; one placed at class level covers every action in the class
- Middleware order decides whether the check runs at all: `UseAuthentication()` must come before `UseAuthorization()`, and both before endpoint execution. Anything served earlier in the pipeline, such as a `UseStaticFiles()` call placed above them, is delivered without either
- Neither call missing from `Program.cs` is by itself the finding: `WebApplication` inserts both automatically after `UseRouting` when `AddAuthentication`/`AddAuthorization` registered their services. Order is what to check where user code calls them explicitly
- .NET 9's `MapStaticAssets()` serves through endpoint routing rather than pipeline position, so a fallback policy does reach it and anonymous access must be granted deliberately by adding `AllowAnonymousAttribute` to its endpoint metadata - the reverse of the `UseStaticFiles()` case above
- Minimal APIs inherit nothing from MVC conventions - apply `.RequireAuthorization()` to the endpoint or, better, to a `MapGroup()` so sibling routes added later are covered by the group rather than by memory
- Endpoints registered by infrastructure helpers carry no authorization metadata of their own: `MapHealthChecks()`, metrics scraping endpoints, `MapHub()` for SignalR, and `UseSwagger()`/`UseSwaggerUI()` are all anonymous unless told otherwise, and a published API description gives away the route inventory an attacker would otherwise have to guess. SignalR's documented control is `[Authorize]` on the hub class or method rather than metadata on `MapHub()`
- Check for the OpenAPI successor as well as Swashbuckle: from .NET 9 the Web API template drops `UseSwagger()`/`UseSwaggerUI()` for `AddOpenApi()`/`MapOpenApi()`, which serves `/openapi/{documentName}.json` and enables no authorization checks by default. Secure it with `.RequireAuthorization(...)`, or map it only in Development as the .NET 10 template does
- gRPC services need `[Authorize]` on the service class or `.RequireAuthorization()` on `MapGrpcService()`; the interceptor pipeline does not supply one by default
- An operation reachable both from an endpoint and from a queue or `IHostedService` has no `ClaimsPrincipal` on the background path, so put the identity requirement in the shared service rather than in the controller

## Taint Sinks

`app.MapGet()`/`MapPost()` without `.RequireAuthorization()`, controllers or actions with no `[Authorize]`, `[AllowAnonymous]`, `MapHealthChecks()`, `MapHub()`, `MapGrpcService()` without authorization metadata, `MapOpenApi()` or `UseSwaggerUI()` reachable in production

## Remediation Steps

- Locate - Enumerate every endpoint registration in `Program.cs`/`Startup.cs`: controller routes, `MapGet`/`MapPost` calls, `MapGroup` blocks, hubs, gRPC services, health checks, and `MapOpenApi()` or the Swashbuckle calls it replaced
- Diff against coverage - Determine which of them carry authorization metadata, whether from `[Authorize]`, `.RequireAuthorization()`, or a fallback policy
- Confirm identity is never established - If the endpoint checks a role or ownership but does so wrongly, that is CWE-862 or CWE-863 rather than this entry
- Apply the fix - Set `FallbackPolicy` to require an authenticated user, then add `.RequireAuthorization()` to any endpoint registered outside a covered group
- Audit the exceptions - Review every `[AllowAnonymous]` and confirm each is an intentionally public endpoint, not a leftover from development
- Verify pipeline order - Where `Program.cs` calls them explicitly, confirm `UseAuthentication()` precedes `UseAuthorization()` and that no endpoint-serving middleware runs before them
- Test directly against the endpoint - Send an unauthenticated request straight to each route rather than driving the UI, and confirm a rejection rather than a 200. Under cookie authentication before .NET 10 that rejection is a 302 to the login page; .NET 10 is where known API endpoints - `[ApiController]`, JSON minimal APIs, `TypedResults` returns, SignalR - began answering 401/403 instead of redirecting
