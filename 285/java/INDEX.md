# CWE-285: Improper Authorization - Java / Spring Security

## LLM Guidance

In Spring Security applications, improper authorization occurs when endpoints or methods lack role or permission checks, allowing authenticated users to access resources or perform actions they should not. The primary mechanisms are method-level security (`@PreAuthorize`, `@Secured`) and HTTP security configuration (`http.authorizeHttpRequests()`). Both must be configured; relying on only one creates gaps.

## Key Principles

- Enable method security with `@EnableMethodSecurity` and apply `@PreAuthorize` to service methods
- Define HTTP authorization rules in `SecurityFilterChain` with least-privilege defaults (`anyRequest().authenticated()`)
- Prefer `@PreAuthorize` with SpEL expressions over `@Secured` for fine-grained role/permission checks
- Never derive authorization decisions from user-supplied input (e.g., a `role` request parameter)
- Test each protected endpoint with a lower-privileged account to confirm access is denied

## Remediation Steps

- Enable method security — add `@EnableMethodSecurity` to a `@Configuration` class
- Apply `@PreAuthorize("hasRole('ADMIN')")` (or `hasAuthority`) to service methods performing privileged operations
- Configure HTTP rules — in `SecurityFilterChain`, call `.requestMatchers("/admin/**").hasRole("ADMIN")` before the catch-all `.anyRequest().authenticated()`
- Avoid `permitAll()` on sensitive paths; audit every `permitAll()` and `anonymous()` rule
- Use `@PostAuthorize` or query-level filtering (`@PostFilter`) to enforce object-level authorization where needed
- Verify with integration tests that unauthenticated and lower-privileged requests receive 401/403

## Safe Pattern

```java
// Enable method-level security
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/admin/**").hasRole("ADMIN")
            .requestMatchers("/api/public/**").permitAll()
            .anyRequest().authenticated()
        );
        return http.build();
    }
}

// Service with method-level check
@Service
public class ReportService {

    @PreAuthorize("hasRole('MANAGER') or hasAuthority('REPORTS_READ')")
    public List<Report> getReports() {
        return reportRepository.findAll();
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteReport(Long id) {
        reportRepository.deleteById(id);
    }
}
```
