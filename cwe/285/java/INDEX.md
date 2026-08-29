# CWE-285: Improper Authorization - Java

## LLM Guidance

In Spring Security applications, improper authorization occurs when endpoints or methods lack role or permission checks, allowing authenticated users to access resources or perform actions they should not. The primary mechanisms are method-level security (`@PreAuthorize`, `@Secured`) and HTTP security configuration (`http.authorizeHttpRequests()`). Both must be configured; relying on only one creates gaps.

## Key Principles

- Enable method security with `@EnableMethodSecurity` (Spring Security 5.6+; `@EnableGlobalMethodSecurity` is the deprecated predecessor) and apply `@PreAuthorize` to service methods. Enforcement is a Spring AOP proxy, so it does not cover a call the bean makes to itself on `this`, nor a `private` or `final` method
- Define HTTP authorization rules in `SecurityFilterChain` with least-privilege defaults (`anyRequest().authenticated()`)
- Prefer `@PreAuthorize` with SpEL expressions over `@Secured`, which is enabled only by `@EnableMethodSecurity(securedEnabled = true)` and is off by default - so a `@Secured` annotation on its own may be enforcing nothing. `hasRole('ADMIN')` matches the authority `ROLE_ADMIN`; `hasAuthority` matches literally
- Never derive authorization decisions from user-supplied input (e.g., a `role` request parameter)
- Test each protected endpoint with a lower-privileged account to confirm access is denied

## Taint Sinks

`@PreAuthorize`, `@PostAuthorize`, `@Secured`, `@EnableMethodSecurity`, `authorizeHttpRequests`, `requestMatchers()`, `permitAll()`, `anonymous()`, `hasRole()`

## Remediation Steps

- Enable method security - add `@EnableMethodSecurity` to a `@Configuration` class
- Apply `@PreAuthorize("hasRole('ADMIN')")` (or `hasAuthority`) to service methods performing privileged operations
- Configure HTTP rules - in `SecurityFilterChain`, call `.requestMatchers("/admin/**").hasRole("ADMIN")` before the catch-all `.anyRequest().authenticated()`
- Avoid `permitAll()` on sensitive paths; audit every `permitAll()` and `anonymous()` rule
- Enforce object-level authorization in `@PreAuthorize` against a bean that loads the record, or by scoping the repository query to the owner. `@PostAuthorize` and `@PostFilter` run after the method body, so on a method that writes the change is already made when the check fails - Spring warns specifically against pairing `@PostAuthorize` with `@Transactional`
- Verify with MockMvc tests that lower-privileged requests are denied. `ExceptionTranslationFilter` renders `AccessDeniedException` as 403 only for an authenticated caller; an anonymous one is sent to the `AuthenticationEntryPoint`, and a method called outside an HTTP request must handle the exception itself
