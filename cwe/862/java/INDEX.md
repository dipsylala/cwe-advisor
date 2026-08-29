# CWE-862: Missing Authorization - Java

## LLM Guidance

In Spring applications, Missing Authorization typically appears as a `@RestController` method secured only by the global authentication filter, so any logged-in user can call it, with no `@PreAuthorize`, `@Secured`, or matching `authorizeHttpRequests` rule restricting it by role or ownership. It also appears as a new endpoint added after the `SecurityFilterChain` matcher list was written, so it falls through to a broader default rule instead of the specific rule it needs. Fix by adding method-level authorization (`@PreAuthorize`) or a matching `authorizeHttpRequests` rule, using SpEL expressions that reference the resource for ownership checks.

## Key Principles

- Enable method security (`@EnableMethodSecurity`, Spring Security 5.6+; `@EnableGlobalMethodSecurity` is the deprecated predecessor a legacy codebase will have) and annotate sensitive service or controller methods with `@PreAuthorize("hasRole('ADMIN')")` or a SpEL expression referencing the resource, rather than relying only on URL-pattern rules. Spring Boot's security starter does not activate method-level authorization on its own
- `@Secured` is enabled only by `@EnableMethodSecurity(securedEnabled = true)`, which is off by default, so treat a `@Secured` annotation as evidence of intent rather than of enforcement; `@PreAuthorize` supersedes it
- `hasRole('ADMIN')` matches the authority `ROLE_ADMIN` - it is a shortcut for `hasAuthority` that adds the configured prefix - while `hasAuthority('ORDER_MANAGE')` matches literally. Mixing the two spellings is how a rule silently denies everyone or admits everyone
- In `SecurityFilterChain`, order `authorizeHttpRequests` matchers from most specific to least specific and end with `.anyRequest().authenticated()` or `.denyAll()` so new routes cannot silently fall through to an unintended broad rule
- For resource-level checks, use `@PreAuthorize("@orderSecurity.isOwner(#id, authentication.name)")` calling a bean that loads the entity and compares ownership, not just a role check
- Prefer `@PreAuthorize` at the service layer over controller-only checks so every caller that goes through the bean's proxy is covered. Method security is proxy-based, so a call the bean makes to itself on `this` bypasses the advice entirely, and `private`, `final`, and package-private methods cannot be advised at all - move the annotated method onto a collaborating bean rather than annotating a method its own class calls
- Unauthorized calls should raise `AccessDeniedException` - do not catch and suppress it. `ExceptionTranslationFilter` turns it into a 403 only for an authenticated caller; an anonymous one is sent to the `AuthenticationEntryPoint` instead, and a method invoked outside an HTTP request has no filter to translate it, so a scheduled job must handle the exception itself. That is the right answer for a role or authority gate; for ownership of a guessable identifier, prefer a repository method scoped by owner (`findByIdAndOwnerId`) whose empty result becomes a 404
- On Jakarta EE without Spring Security, the equivalents are `@RolesAllowed` on the EJB or JAX-RS resource and a `SecurityContext.isUserInRole()` check. On JAX-RS the annotations are not part of the specification and are inert until the implementation's feature is registered - in Jersey, `register(RolesAllowedDynamicFeature.class)` - so confirm that registration before treating an annotated resource as protected. `@PermitAll` on a class applies to every method that does not override it
- `hasRole('CUSTOMER')` proves the caller's role and nothing about the record being touched - pair it with an ownership check against a server-loaded copy of the resource
- Cover the authorization rules with `MockMvc` (or equivalent) tests that call the endpoint directly as a second user, since a UI-driven test never exercises the path an attacker uses

## Taint Sinks

`@GetMapping`, `@PostMapping`, `@PutMapping`, `@DeleteMapping`, `@RequestMapping`, `@PreAuthorize`, `@Secured`, `@RolesAllowed`, `authorizeHttpRequests`, `@EnableMethodSecurity`

## Remediation Steps

- Locate - Identify `@RestController`/`@Controller` methods and service methods that perform sensitive actions or return sensitive data
- Check for missing checks - Confirm the method has no `@PreAuthorize`/`@Secured` annotation and no matching `authorizeHttpRequests` rule beyond generic authentication
- Add role-based authorization - Apply `@PreAuthorize("hasRole('ADMIN')")` or `@PreAuthorize("hasAuthority('ORDER_MANAGE')")` to the method
- Add resource-based authorization - For entity-specific actions, reference a security bean from the SpEL expression that verifies the authenticated user owns or has a granted relationship to the specific record; the `@beanName.method(...)` reference resolves against the bean's name, which defaults to the uncapitalized class name (`OrderSecurity` becomes `orderSecurity`), so name it explicitly only when the class name does not match the expression
- Reconcile with `SecurityFilterChain` - Ensure `authorizeHttpRequests` matchers cover the new route explicitly and that the chain ends with a deny-by-default rule
- Harden configuration - Confirm `@EnableMethodSecurity` is active, and that `securedEnabled = true` is set if any `@Secured` annotation is being relied on
- Test - Write `@WithMockUser` MockMvc tests that call each endpoint as an authenticated user lacking the required role and assert 403, and as a user who owns a different record and assert the 404 that a repository query scoped by owner returns. `@WithMockUser(roles = "X")` grants `ROLE_X` while `authorities = "X"` grants `X` verbatim, so pick the attribute that matches the expression under test. Calling the annotated bean directly instead of through MockMvc raises `AccessDeniedException` rather than producing a status
