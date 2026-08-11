# CWE-863: Incorrect Authorization - Java

## LLM Guidance

In Spring applications, Incorrect Authorization commonly appears as `@PreAuthorize("hasRole('ADMIN')")` used alone on an endpoint that also needs an ownership check, a denylist role comparison in a custom filter (`if (!role.equals("ADMIN"))` inverted incorrectly), or a `@Secured`/`@PreAuthorize` check present on the service method but missing on a newer controller path that calls the repository directly. Fix flawed logic by combining role checks with a SpEL expression that calls a bean-backed ownership check, and ensure every entry point to the resource goes through the same authorization method.

## Key Principles

- Use `@PreAuthorize` or `@PostAuthorize` with SpEL expressions that combine role and ownership, e.g. `hasRole('ADMIN') or @orderSecurity.isOwner(#id, authentication.name)`, rather than a role check alone
- Never derive the authorization decision from a role or user ID submitted in the request body or a query parameter - resolve identity from `Authentication`/`SecurityContextHolder`
- Implement ownership checks as a bean method that loads the resource from the repository and compares its owner field to the authenticated principal, not from a cached or client-asserted value
- Apply the same `@PreAuthorize` expression (or a shared service-layer check) on every controller method that reaches the resource, including PUT/PATCH/DELETE and any bulk/admin variant endpoints
- Avoid negated role comparisons (`!role.equals("ADMIN")`) in custom filters; use Spring Security's role/authority matching, which treats unmatched authorities as denied by default
- Enable method security explicitly (`@EnableMethodSecurity`) and verify `@PreAuthorize` is actually active - a missing annotation processor or disabled method security silently allows all calls through

## Remediation Steps

- Locate - Find `@PreAuthorize`/`@Secured` annotations that check role only, and any custom filters with inline `if` role comparisons
- Trace data flow - Identify every controller method and repository call path that reaches the resource, including ones added after the original check was written
- Replace the unsafe pattern - Convert role-only checks to a combined SpEL expression that also verifies ownership via a bean method
- Bind, encode, validate, or authorize - Implement the ownership bean method to load the resource server-side and compare its owner ID to `authentication.getName()` or the principal's user ID claim
- Break taint after allowlist validation - Resolve the caller's authorities from `SecurityContextHolder`, not from any request parameter, before evaluating the expression
- Harden configuration - Confirm `@EnableMethodSecurity` is present and add a default-deny rule in `SecurityFilterChain` for unmatched routes
- Test - Add `@WithMockUser` tests for a non-owner with a valid role attempting access, and for a role not in the allowlist, confirming both return 403

## Safe Pattern

```java
// SAFE: role check combined with a bean-backed ownership check
@Service("orderSecurity")
public class OrderSecurityService {

    private final OrderRepository orderRepository;

    public OrderSecurityService(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    public boolean isOwner(Long orderId, String username) {
        return orderRepository.findById(orderId)
            .map(order -> order.getOwnerUsername().equals(username))
            .orElse(false);
    }
}

@RestController
@RequestMapping("/orders")
public class OrderController {

    private final OrderRepository orderRepository;

    public OrderController(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    // Admins pass on role alone; other authenticated users must own the order.
    @PreAuthorize("hasRole('ADMIN') or @orderSecurity.isOwner(#id, authentication.name)")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteOrder(@PathVariable Long id) {
        orderRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }
}
```
