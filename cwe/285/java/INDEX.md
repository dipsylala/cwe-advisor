# CWE-285: Improper Authorization - Java

## LLM Guidance

In Spring Security applications, improper authorization occurs when endpoints or methods lack role or permission checks, allowing authenticated users to reach resources or operations they should not. The two mechanisms are method-level security (`@PreAuthorize`) and HTTP security configuration (`http.authorizeHttpRequests()`), and they cover different gaps: an unannotated method is unprotected by the first, which is why the second needs a catch-all rule.

## Key Principles

- Enable method security with `@EnableMethodSecurity` on a `@Configuration` class (Spring Security 5.6+) - Spring Boot's security starter does not activate it. Its predecessor `@EnableGlobalMethodSecurity` is deprecated since 5.8 and still present in 7.x, and defaults `prePostEnabled` to `false` where the replacement defaults it to `true`
- Enforcement is a Spring AOP proxy, so it does not cover a call the bean makes to itself on `this`, nor a `private`, `final` or package-private method, nor any method of a `final` class. AspectJ weaving has no such limit, since it applies the advice in the bytecode rather than through a proxy
- Prefer `@PreAuthorize` with SpEL over `@Secured`, which is inert unless `@EnableMethodSecurity(securedEnabled = true)`: the attribute defaults to `false` and nothing warns at startup, so the annotation's presence is not evidence the method is protected. `hasRole('ADMIN')` matches the authority `ROLE_ADMIN` and `hasAuthority` matches literally, with the prefix configurable through a `GrantedAuthorityDefaults` bean
- Define HTTP rules in a `SecurityFilterChain` ending in `anyRequest().authenticated()`. From Spring Security 6.0 a request matching no rule is denied where 5.x abstained and let it through, so any claim about the default needs that version boundary. `authorizeRequests` is deprecated for removal since 6.1 and removed in 7.0
- Rules are first-match, not most-specific, and the DSL enforces the ordering: `.requestMatchers(...)` after `anyRequest()` throws `IllegalStateException: Can't configure requestMatchers after anyRequest` at startup. A new rule has to be inserted above the catch-all, not appended after it
- A class-level annotation applies to every method in the class and a method-level one overrides it; a class inheriting the same annotation from two different interfaces fails at startup, which is resolved by annotating the concrete method
- These annotation and DSL names locate the configuration rather than the defect, since the finding is normally the absence of a rule. Grep them to enumerate what is protected and compare that against the endpoints and service methods that exist; `permitAll()` and `anonymous()` are the two whose presence is itself worth auditing
- Never derive an authorization decision from user-supplied input, such as a `role` request parameter

## Taint Sinks

`@PreAuthorize`, `@PostAuthorize`, `@Secured`, `@EnableMethodSecurity`, `authorizeHttpRequests`, `authorizeRequests`, `requestMatchers()`, `permitAll()`, `anonymous()`, `hasRole()`

## Remediation Steps

- Enable method security - add `@EnableMethodSecurity` to a `@Configuration` class
- Apply `@PreAuthorize("hasRole('ADMIN')")` (or `hasAuthority`) to service methods performing privileged operations, and confirm the caller reaches them through the proxy rather than from inside the same bean
- Configure HTTP rules - insert `.requestMatchers("/admin/**").hasRole("ADMIN")` above the existing `.anyRequest()` rule rather than after it
- Audit every `permitAll()` and `anonymous()` rule on a sensitive path
- Enforce object-level authorization in `@PreAuthorize` against a bean that loads the record, or by scoping the repository query to the owner. `@PostAuthorize` and `@PostFilter` run after the method body, so on a method that writes, the change is already made when the check fails - Spring's remedies are to `@PostAuthorize` the read and then write, or to order `@EnableTransactionManagement` ahead of `@EnableMethodSecurity`
- Verify with tests that a lower-privileged caller is denied. `ExceptionTranslationFilter` renders `AccessDeniedException` as 403 only for a fully authenticated caller - an anonymous *or remember-me* one is sent to the `AuthenticationEntryPoint` instead - and a method invoked outside an HTTP request has to handle the exception itself
- On a Jersey/JAX-RS resource, set `jersey.config.server.response.setStatusOverSendError` to `true` on the `ResourceConfig`, or Jersey commits the response before Spring Security can report the failure
