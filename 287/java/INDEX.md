# CWE-287: Improper Authentication - Java

## LLM Guidance

In Spring applications, Improper Authentication commonly appears as a custom `AuthenticationProvider` whose `authenticate()` method returns a successful `Authentication` without actually validating the credential, or whose `supports()` check is too broad and lets `ProviderManager` delegate unintended authentication types to it. It also appears in JWT handling with `io.jsonwebtoken` (jjwt) when code calls the unsigned `parse()`/`parseClaimsJwt()` methods or uses a loosely-typed key, allowing an attacker-controlled `alg` header (including `none`) to decide how the token is verified. Fix by making `authenticate()` throw on any unverified credential and by parsing tokens only with `parseSignedClaims()`/`parseClaimsJws()` bound to a correctly-typed verification key.

## Key Principles

- In a custom `AuthenticationProvider`, only return a successful `Authentication` after verifying the credential (e.g., `PasswordEncoder.matches()`); throw `BadCredentialsException` on any failure or missing credential - never fall through to a default success.
- Scope `AuthenticationProvider.supports(Class<?> authentication)` to the exact `Authentication` subtype it handles so `ProviderManager` cannot delegate unrelated authentication attempts to it.
- For jjwt, always call `parseSignedClaims()` (0.12+) or `parseClaimsJws()` (0.11.x) against a strongly-typed `SecretKey`/`PublicKey` via `verifyWith()`/`setSigningKey()`; never use the unsigned `parse()`/`parseClaimsJwt()` variants, which accept tokens with `alg: none`.
- Generate JWT signing keys with sufficient entropy, e.g. `Jwts.SIG.HS256.key().build()`, and load them from configuration or a secret store rather than a hardcoded string.
- For resource-server JWT validation, prefer Spring Security's `NimbusJwtDecoder` with an explicit `macAlgorithm()`/`signatureAlgorithm()` so the accepted algorithm is pinned in code, not inferred from the token.
- Enforce authentication in the `SecurityFilterChain` in addition to the provider, so a misconfigured provider cannot expose an otherwise-protected route.

## Remediation Steps

- Locate - Find custom `AuthenticationProvider`/`AuthenticationManager` implementations, JWT parsing filters, and `Jwts.parser()`/`Jwts.parserBuilder()` call sites
- Trace data flow - Follow the credential from the login endpoint or the token from the `Authorization` header through `authenticate()` or the JWT filter into `SecurityContextHolder`
- Replace the unsafe pattern - Change `parse()`/`parseClaimsJwt()` to `parseSignedClaims()`/`parseClaimsJws()` bound to a typed key; change provider logic that returns success without a credential check
- Bind, encode, validate, or authorize - Verify the password via `PasswordEncoder.matches(rawPassword, user.getPassword())` and verify the JWT signature via a key whose algorithm family matches the expected header `alg`
- Break taint after allowlist validation - Populate `SecurityContextHolder` only from the `Authentication` returned after a successful provider call or JWT verification, never from unverified claims
- Harden configuration - Rotate JWT signing secrets, confirm the verification key type matches the intended algorithm family, and check the `SecurityFilterChain` leaves no route unauthenticated by omission
- Test - Write `@WithMockUser` and forged-token tests: an invalid password must throw `BadCredentialsException`, and a token with `alg: none` or a mismatched algorithm must be rejected with 401

## Safe Pattern

```java
// SAFE: jjwt 0.12+ - verify with a typed key; alg:none and mismatched algorithms are rejected
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Claims;
import javax.crypto.SecretKey;

SecretKey key = Jwts.SIG.HS256.key().build(); // load a persisted key in production

Jws<Claims> jws = Jwts.parser()
        .verifyWith(key)           // binds verification to an HMAC key family
        .build()
        .parseSignedClaims(token); // throws on unsigned, alg:none, or algorithm mismatch

String subject = jws.getPayload().getSubject();
```

```java
// SAFE: AuthenticationProvider that verifies the password before returning success
@Component
public class AccountAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public AccountAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication auth) throws AuthenticationException {
        String username = auth.getName();
        String rawPassword = (String) auth.getCredentials();
        UserDetails user = userDetailsService.loadUserByUsername(username);

        if (rawPassword == null || !passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }
        return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```
