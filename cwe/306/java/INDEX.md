# CWE-306: Missing Authentication for Critical Function - Java

## LLM Guidance

In Spring Security the requirement lives in the `SecurityFilterChain` bean, not in the controller, so a missing check is usually an ordering or coverage problem in `authorizeHttpRequests` rather than anything visible in the handler. Rules are evaluated in declaration order and the first match wins, which makes a broad `permitAll()` near the top silently shadow every stricter rule below it. Fix by ending the chain with `anyRequest().authenticated()` and narrowing the permitted matchers until only genuinely public paths match them.

## Key Principles

- Terminate every `authorizeHttpRequests` chain with `anyRequest().authenticated()`, which is Spring Security's own recommendation - but check the version before writing up the reason. From 6.0 a request matching no rule is denied; 5.x abstained and the `AuthorizationFilter` let it through. So an unterminated chain is genuinely open only on 5.x, and on 6.0+ the finding is a path reaching a `permitAll()` rule it should not, not a path reaching no rule
- Rule order is the control: `requestMatchers("/**").permitAll()` placed before a stricter matcher wins for every request, and the later rule that looks like the protection never executes. Read the chain top-down as the framework does
- `WebSecurityCustomizer.ignoring()` removes the path from the filter chain entirely - no authentication, and no security headers either. Prefer `permitAll()` inside the chain, which keeps the rest of the filter behaviour for genuinely public paths. Spring Security logs a startup warning naming each ignored matcher and pointing at `permitAll`, so the application log locates these as reliably as the configuration does
- Multiple `SecurityFilterChain` beans are selected by `@Order` and by each chain's `securityMatcher`; a broadly matching chain registered first swallows requests meant for a later, stricter chain, which then never runs. From 6.5 an `UnreachableFilterChainException` fails startup when an any-request chain precedes another or two chains share a matcher - but not when the earlier chain is merely broad, which is the form this finding usually takes
- `@PreAuthorize`/`@PostAuthorize` are inert without `@EnableMethodSecurity` - the annotations compile, the tests that assert on them can pass, and no check runs at runtime
- Actuator endpoints are a distinct surface. Only `health` is exposed by default; `management.endpoints.web.exposure.include=*` publishes `/actuator/env` and `/actuator/threaddump`, though from Spring Boot 3.5 `heapdump` needs `management.endpoint.heapdump.access=unrestricted` as well as exposure, its `defaultAccess` having become `NONE`. Gate the rest with `EndpointRequest.toAnyEndpoint()`, whose package moved under `org.springframework.boot.security.autoconfigure` in Boot 4.0
- Boot secures every actuator but `health` by itself only while the application declares no `SecurityFilterChain` bean of its own. Declaring one makes that auto-configuration back off completely, so a chain written for the application's own paths is what exposed the management surface
- On Jakarta EE without Spring Security the equivalents are `@RolesAllowed`, `@PermitAll` and `@DenyAll`, where a method-level annotation overrides the class-level one, so a class annotated `@PermitAll` covers every method that does not. They carry the same activation trap as `@PreAuthorize`: in Jakarta REST nothing enforces them until `RolesAllowedDynamicFeature` is registered as a provider, so a resource covered in annotations can still be entirely open. A `<security-constraint>` in `web.xml` is a separate, URL-pattern control at the servlet layer rather than what activates them

## Taint Sinks

`authorizeHttpRequests` chains with no `anyRequest().authenticated()`, `permitAll()` on a broad matcher, `WebSecurityCustomizer.ignoring()`, `@PreAuthorize` without `@EnableMethodSecurity`, `management.endpoints.web.exposure.include`, `@PermitAll` at class level, `@RolesAllowed` with no `RolesAllowedDynamicFeature` registered

## Remediation Steps

- Locate - Find every `SecurityFilterChain` bean and read its `securityMatcher` and `authorizeHttpRequests` rules in declaration order, along with any `WebSecurityCustomizer`
- Diff against coverage - List the application's controller mappings and determine which rule each one matches. On 5.x a mapping reaching no rule is the gap; on 6.0+ it is denied, so the gap is a mapping reaching a `permitAll()` or an `ignoring()` matcher instead
- Confirm identity is never established - A path that authenticates but skips a role or ownership check is CWE-862 or CWE-863, not this entry
- Apply the fix - Add `anyRequest().authenticated()` as the final rule, then narrow any `permitAll()` matcher until it covers only intentionally public paths
- Move ignores into the chain - Replace `WebSecurityCustomizer.ignoring()` with a `permitAll()` matcher so the path keeps the filter chain's other protections
- Cover the management surface - Restrict actuator exposure and add an `EndpointRequest.toAnyEndpoint()` rule requiring authentication, remembering that declaring the application's own chain is what withdrew Boot's
- Test directly against the endpoint - Issue unauthenticated requests to each mapping, including actuator paths, and confirm a 401 rather than a 200
