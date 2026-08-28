# CWE-862: Missing Authorization - Java

## LLM Guidance

In Spring applications, Missing Authorization typically appears as a `@RestController` method secured only by the global authentication filter, so any logged-in user can call it, with no `@PreAuthorize`, `@Secured`, or matching `authorizeHttpRequests` rule restricting it by role or ownership. It also appears as a new endpoint added after the `SecurityFilterChain` matcher list was written, so it falls through to a broader default rule instead of the specific rule it needs. Fix by adding method-level authorization (`@PreAuthorize`) or a matching `authorizeHttpRequests` rule, using SpEL expressions that reference the resource for ownership checks.

## Key Principles

- Enable method security (`@EnableMethodSecurity`) and annotate sensitive service or controller methods with `@PreAuthorize("hasRole('ADMIN')")` or a SpEL expression referencing the resource, rather than relying only on URL-pattern rules
- In `SecurityFilterChain`, order `authorizeHttpRequests` matchers from most specific to least specific and end with `.anyRequest().authenticated()` or `.denyAll()` so new routes cannot silently fall through to an unintended broad rule
- For resource-level checks, use `@PreAuthorize("@orderSecurity.isOwner(#id, authentication.name)")` calling a bean that loads the entity and compares ownership, not just a role check
- A valid role does not imply ownership of every record of that type; pair role checks with resource-level checks for actions on a specific entity
- Prefer `@PreAuthorize` at the service layer over controller-only checks so the rule applies regardless of which controller or scheduled job invokes the method
- Unauthorized calls should raise `AccessDeniedException`, handled by Spring Security's default `AccessDeniedHandler` as a 403 - do not catch and suppress it
- `hasRole('CUSTOMER')` proves the caller's role and nothing about the record being touched - pair it with an ownership check against a server-loaded copy of the resource
- Cover the authorization rules with `MockMvc` (or equivalent) tests that call the endpoint directly as a second user, since a UI-driven test never exercises the path an attacker uses

## Taint Sinks

`@GetMapping`, `@PostMapping`, `@PutMapping`, `@DeleteMapping`, `@RequestMapping` methods lacking `@PreAuthorize`/`@Secured`

## Remediation Steps

- Locate - Identify `@RestController`/`@Controller` methods and service methods that perform sensitive actions or return sensitive data
- Check for missing checks - Confirm the method has no `@PreAuthorize`/`@Secured` annotation and no matching `authorizeHttpRequests` rule beyond generic authentication
- Add role-based authorization - Apply `@PreAuthorize("hasRole('ADMIN')")` or `@PreAuthorize("hasAuthority('ORDER_MANAGE')")` to the method
- Add resource-based authorization - For entity-specific actions, reference a security bean from the SpEL expression that verifies the authenticated user owns or has a granted relationship to the specific record; the bean needs an explicit name (`@Component("orderSecurity")`) for the `@beanName.method(...)` reference to resolve
- Reconcile with `SecurityFilterChain` - Ensure `authorizeHttpRequests` matchers cover the new route explicitly and that the chain ends with a deny-by-default rule
- Harden configuration - Confirm `@EnableMethodSecurity` is active so `@PreAuthorize` annotations are enforced
- Test - Write `@WithMockUser` integration tests that call each endpoint as an authenticated user lacking the required role or ownership and assert HTTP 403
