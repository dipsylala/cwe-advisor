# CWE-287: Improper Authentication - Java

## LLM Guidance

In Spring applications, Improper Authentication commonly appears as a custom `AuthenticationProvider` whose `authenticate()` method returns a successful `Authentication` without actually validating the credential, or whose `supports()` check is too broad and lets `ProviderManager` delegate unintended authentication types to it. It also appears in JWT handling with `io.jsonwebtoken` (jjwt) when code parses against a loosely-typed key, or - on jjwt before 0.12 - calls the unsigned `parse()`/`parseClaimsJwt()` methods, letting an attacker-controlled `alg` header decide how the token is verified. Fix by making `authenticate()` throw on any unverified credential and by parsing tokens only with `parseSignedClaims()`/`parseClaimsJws()` bound to a correctly-typed verification key.

## Key Principles

- In a custom `AuthenticationProvider`, only return a successful `Authentication` after verifying the credential (e.g., `PasswordEncoder.matches()`); throw `BadCredentialsException` on any failure or missing credential - never fall through to a default success.
- Scope `AuthenticationProvider.supports(Class<?> authentication)` to the exact `Authentication` subtype it handles so `ProviderManager` cannot delegate unrelated authentication attempts to it.
- For jjwt, parse with `parseSignedClaims()` (0.12+) or `parseClaimsJws()` (0.11.x) against a strongly-typed `SecretKey`/`PublicKey` via `verifyWith()`/`setSigningKey()`. From 0.12 the unsecured paths reject an `alg: none` token by default and accept one only after `JwtParserBuilder.unsecured()` is called, so on a current version the finding is that opt-in rather than the method choice; on 0.11.x and earlier they accept `none` outright. Both are deprecated since 0.12, not removed.
- Generate JWT signing keys with sufficient entropy, e.g. `Jwts.SIG.HS256.key().build()`, and load them from configuration or a secret store rather than a hardcoded string.
- For resource-server JWT validation with `NimbusJwtDecoder`, pin the algorithm on the builder actually in use: `jwsAlgorithm(...)` on `withJwkSetUri(...)`, `signatureAlgorithm(...)` on `withPublicKey(...)`, `macAlgorithm(...)` on `withSecretKey(...)` - so the accepted algorithm comes from configuration rather than the token's own header.
- Enforce authentication in the `SecurityFilterChain` in addition to the provider, so a misconfigured provider cannot expose an otherwise-protected route.
- Spring Security's `sessionFixation()` default is `changeSessionId()` on Servlet 3.1+ containers (since Spring Security 3.2, where `ChangeSessionIdAuthenticationStrategy` was introduced), which keeps the session and its attributes but issues a new identifier; `migrateSession()` (new session, attributes copied) is the older default, still selected on Servlet 3.0 and earlier, `newSession()` starts empty, and `none()` disables the protection entirely - confirm which one a custom configuration selects
- `UsernameNotFoundException` is mapped to a generic `BadCredentialsException` by `DaoAuthenticationProvider` only while `hideUserNotFoundExceptions` is left true - turning it off to improve logging discloses which usernames exist
- `DaoAuthenticationProvider` encodes a fixed `userNotFoundPassword` and runs `matches()` against it when `loadUserByUsername` throws, so replacing a custom provider with a `UserDetailsService` plus a `PasswordEncoder` bean is usually the cheapest fix for a login-timing finding. The encode is lazy rather than at start-up - `prepareTimingAttackProtection()` is called from `retrieveUser()` under a null check, and `setPasswordEncoder(...)` resets it - and the decoy `matches()` runs only on `UsernameNotFoundException` and only while `authentication.getCredentials()` is non-null, so another failure mode, or an attempt sent with no credential, is not covered. On Spring Security 7.0 its no-arg constructor and `setUserDetailsService` are gone, deprecated in 6.5: construct it with the `UserDetailsService`
- If a custom provider stays, catch `UsernameNotFoundException` and run `PasswordEncoder.matches()` against a dummy hash before throwing `BadCredentialsException`; letting the exception propagate returns without hashing while a wrong password pays the full BCrypt cost
- That dummy must be a genuine 60-character BCrypt hash at the encoder's own strength, and must also stand in when `user.getPassword()` is null (an SSO-only row) - `BCryptPasswordEncoder` rejects `""` or a malformed hash on a format check without hashing; through 6.4.x it logs `Empty encoded password` on every such login, while in 7.0 `matches()` moved to `AbstractValidatingPasswordEncoder`, which returns false with no log

## Taint Sinks

`AuthenticationProvider.authenticate()` without credential check, `Jwts.parser().parse()`/`parseClaimsJwt()` unsigned variants

## Remediation Steps

- Locate - Find custom `AuthenticationProvider`/`AuthenticationManager` implementations, JWT parsing filters, and `Jwts.parser()`/`Jwts.parserBuilder()` call sites
- Trace data flow - Follow the credential from the login endpoint or the token from the `Authorization` header through `authenticate()` or the JWT filter into `SecurityContextHolder`
- Replace the unsafe pattern - Change `parse()`/`parseClaimsJwt()` to `parseSignedClaims()`/`parseClaimsJws()` bound to a typed key; change provider logic that returns success without a credential check
- Bind, encode, validate, or authorize - Verify the password via `PasswordEncoder.matches(rawPassword, user.getPassword())` and verify the JWT signature via a key whose algorithm family matches the expected header `alg`
- Break taint after allowlist validation - Populate `SecurityContextHolder` only from the `Authentication` returned after a successful provider call or JWT verification, never from unverified claims
- Harden configuration - Rotate JWT signing secrets, confirm the verification key type matches the intended algorithm family, and check the `SecurityFilterChain` leaves no route unauthenticated by omission
- Test - Write `@WithMockUser` and forged-token tests: an invalid password must throw `BadCredentialsException`, and a token with `alg: none` or a mismatched algorithm must be rejected with 401; time a right password, a wrong password, and an unknown username and assert all three are within noise of each other
