# CWE-306: Missing Authentication for Critical Function - Java

## LLM Guidance

In Spring Security the requirement lives in the `SecurityFilterChain` bean, not in the controller, so a missing check is usually an ordering or coverage problem in `authorizeHttpRequests` rather than anything visible in the handler. Rules are evaluated in declaration order and the first match wins, which makes a broad `permitAll()` near the top silently shadow every stricter rule below it. Fix by ending the chain with `anyRequest().authenticated()` and narrowing the permitted matchers until only genuinely public paths match them.

## Key Principles

- Terminate every `authorizeHttpRequests` chain with `anyRequest().authenticated()`. Without it, a request matching no earlier rule carries no requirement at all, so each new controller path is public until someone adds a matcher for it
- Rule order is the control: `requestMatchers("/**").permitAll()` placed before a stricter matcher wins for every request, and the later rule that looks like the protection never executes. Read the chain top-down as the framework does
- `WebSecurityCustomizer.ignoring()` removes the path from the filter chain entirely - no authentication, and no security headers either. Prefer `permitAll()` inside the chain, which keeps the rest of the filter behaviour for genuinely public paths
- Multiple `SecurityFilterChain` beans are selected by `@Order` and by each chain's `securityMatcher`; a broadly matching chain registered first swallows requests meant for a later, stricter chain, which then never runs
- `@PreAuthorize`/`@PostAuthorize` are inert without `@EnableMethodSecurity` - the annotations compile, the tests that assert on them can pass, and no check runs at runtime
- Actuator endpoints are a distinct surface: `management.endpoints.web.exposure.include=*` publishes `/actuator/env`, `/actuator/heapdump` and `/actuator/threaddump`. Gate them with `EndpointRequest.toAnyEndpoint()` in the chain rather than assuming the application's own matchers cover them
- On Jakarta EE without Spring Security, the equivalent is `@RolesAllowed`/`@DenyAll` on the resource with a `<security-constraint>` in `web.xml`; a class annotated `@PermitAll` covers every method that does not override it

## Taint Sinks

`authorizeHttpRequests` chains with no `anyRequest().authenticated()`, `permitAll()` on a broad matcher, `WebSecurityCustomizer.ignoring()`, `@PreAuthorize` without `@EnableMethodSecurity`, `management.endpoints.web.exposure.include`, `@PermitAll` at class level

## Remediation Steps

- Locate - Find every `SecurityFilterChain` bean and read its `securityMatcher` and `authorizeHttpRequests` rules in declaration order, along with any `WebSecurityCustomizer`
- Diff against coverage - List the application's controller mappings and determine which rule, if any, each one matches; anything reaching no rule is a candidate gap
- Confirm identity is never established - A path that authenticates but skips a role or ownership check is CWE-862 or CWE-863, not this entry
- Apply the fix - Add `anyRequest().authenticated()` as the final rule, then narrow any `permitAll()` matcher until it covers only intentionally public paths
- Move ignores into the chain - Replace `WebSecurityCustomizer.ignoring()` with a `permitAll()` matcher so the path keeps the filter chain's other protections
- Cover the management surface - Restrict actuator exposure and add an `EndpointRequest.toAnyEndpoint()` rule requiring authentication
- Test directly against the endpoint - Issue unauthenticated requests to each mapping, including actuator paths, and confirm a 401 rather than a 200
