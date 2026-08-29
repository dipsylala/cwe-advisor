# CWE-863: Incorrect Authorization - Java

## LLM Guidance

In Spring applications, Incorrect Authorization commonly appears as `@PreAuthorize("hasRole('ADMIN')")` used alone on an endpoint that also needs an ownership check, an inverted role comparison in a custom filter (`if (!role.equals("ADMIN"))`, which also throws when `role` is null - `"ADMIN".equals(role)` does not), or a `@Secured`/`@PreAuthorize` check present on the service method but missing on a newer controller path that calls the repository directly. Fix flawed logic by combining role checks with a SpEL expression that calls a bean-backed ownership check, and ensure every entry point to the resource goes through the same authorization method.

## Key Principles

- Use `@PreAuthorize` with a SpEL expression that combines role and ownership, e.g. `hasRole('ADMIN') or @orderSecurity.isOwner(#id, authentication.name)`, rather than a role check alone. `@PostAuthorize` is not a substitute on a method that writes: it runs after the body, so the change is already made when the check fails, and Spring warns against pairing it with `@Transactional`
- A `#id` reference resolves only if parameter names are discoverable - via `@P`, Spring Data's `@Param`, or compilation with `-parameters` (which Spring Boot sets by default). On an interface, annotations or `-parameters` are the only options
- Where the expression is a role-or-permission disjunction, granting the permission to the role through a `RoleHierarchy` bean (`RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > permission:read")`) keeps the rule in one place instead of in every annotation
- Never derive the authorization decision from a role or user ID submitted in the request body or a query parameter - resolve identity from `Authentication`/`SecurityContextHolder`
- Implement ownership checks as a bean method that loads the resource from the repository and compares its owner field to the authenticated principal, not from a cached or client-asserted value
- Apply the same `@PreAuthorize` expression (or a shared service-layer check) on every controller method that reaches the resource, including PUT/PATCH/DELETE and any bulk/admin variant endpoints
- Avoid hand-written role comparisons in custom filters; use Spring Security's `hasRole`/`hasAuthority` matching, and make the default-deny explicit in the chain rather than assuming the matchers supply it. `hasRole('ADMIN')` matches the authority `ROLE_ADMIN` while `hasAuthority` matches literally
- Enable method security explicitly (`@EnableMethodSecurity`, Spring Security 5.6+) and verify the annotation is actually being applied. Enforcement is a Spring AOP proxy publishing an `AuthorizationManagerBeforeMethodInterceptor`, not annotation processing, so it does not reach a call the bean makes to itself on `this`, nor a `private` or `final` method. `@Secured` additionally needs `securedEnabled = true`, which is off by default
- An `isOwner()`-style helper is only as good as the copy it reads: load the resource server-side and compare against the authenticated principal, never against an id supplied in the same request

## Taint Sinks

`@PreAuthorize`, `@PostAuthorize`, `@Secured`, `@EnableMethodSecurity`, `SecurityContextHolder.getContext()`, `Authentication.getName()`, `authorizeHttpRequests`

## Remediation Steps

- Locate - Find `@PreAuthorize`/`@Secured` annotations that check role only, and any custom filters with inline `if` role comparisons
- Trace data flow - Identify every controller method and repository call path that reaches the resource, including ones added after the original check was written
- Replace the unsafe pattern - Convert role-only checks to a combined SpEL expression that also verifies ownership via a bean method. The `@beanName.isOwner(...)` reference resolves against the bean's name, which defaults to the uncapitalized class name, so name it explicitly only when the two differ
- Bind, encode, validate, or authorize - Implement the ownership bean method to load the resource server-side and compare it against the authenticated principal. `Authentication.getName()` is inherited from `java.security.Principal` and carries whatever the authentication mechanism put there - a username under form login, the `sub` claim under `JwtAuthenticationToken` - so compare it to the field that actually holds that value rather than to a numeric owner id
- Break taint after allowlist validation - Resolve the caller's authorities from `SecurityContextHolder`, not from any request parameter, before evaluating the expression
- Harden configuration - Confirm `@EnableMethodSecurity` is present and end the `authorizeHttpRequests` chain with `anyRequest().denyAll()` (or `.authenticated()`). Rules are evaluated in declaration order and only the first match applies, so the catch-all must come last
- Test - Add `@WithMockUser` MockMvc tests for a non-owner with a valid role, and for a role not in the allowlist, confirming both are denied. Note what the test type returns: through MockMvc the denial is a 403, while invoking the annotated bean directly raises `AccessDeniedException`. `@WithMockUser(roles = "X")` grants `ROLE_X`; `authorities = "X"` grants `X` verbatim
