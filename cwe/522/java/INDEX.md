# CWE-522: Insufficiently Protected Credentials - Java

## LLM Guidance

Insufficiently protected credentials in Java appear as plaintext or weakly hashed passwords, secrets in `.properties` files, and credentials that survive in memory or logs. Separate the two cases before fixing either: a user password is hashed with an adaptive algorithm and never read back, while a credential the application presents to another system is fetched at runtime from a vault. In Spring Security the encoder choice is not simply "use bcrypt" - the framework has a specific answer built around migrating between algorithms.

## Key Principles

- Spring Security's default is `DelegatingPasswordEncoder`, built by `PasswordEncoderFactories.createDelegatingPasswordEncoder()`, not `BCryptPasswordEncoder` used alone. It stores the algorithm in the value as `{bcrypt}$2a$10$...`, which is what lets a deployment verify legacy formats and re-encode to the current one. A bare hash with no `{id}` prefix fails at match time with `IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"`, so migrating an existing column means prefixing it, not just swapping the encoder
- **Floor Spring Security at 6.4.5 or 6.3.9 for bcrypt.** CVE-2025-22228 made `BCryptPasswordEncoder.matches()` return true for any password sharing the first 72 characters, fixed in 6.4.4/6.3.8 - and that fix broke the timing-attack mitigation in `DaoAuthenticationProvider` (CVE-2025-22234), fixed in 6.4.5/6.3.9. The earlier release is not sufficient
- The 72-byte limit is enforced asymmetrically: `BCrypt.hashpw` throws `IllegalArgumentException("password cannot be more than 72 bytes")` when encoding, while the matching path passes `for_check` and skips the check. Existing over-length passwords keep verifying while new ones are rejected, so the failure surfaces at registration and password change rather than at login
- `BCryptPasswordEncoder`'s default strength is 10, and the reference docs ask you to tune it "so that it takes roughly 1 second to verify a password" on the target hardware rather than adopting a number from guidance
- Spring Security ships `Argon2PasswordEncoder` (`@since 5.3`) and `SCryptPasswordEncoder`, both requiring BouncyCastle, so `argon2-jvm` is not the only route. Use the `defaultsForSpringSecurity_v5_8()` factories; the `v5_2` and `v4_1` ones exist for reading old hashes
- **The `char[]` advice cannot be honoured at the Spring layer**, and the entry should say which layer it applies to. `PasswordEncoder.encode` and `matches` take `CharSequence`, and `AbstractValidatingPasswordEncoder` calls `rawPassword.toString()` before hashing. Where `char[]` does apply is the JDK's own APIs - `Console.readPassword`, `JPasswordField.getPassword`, and `PBEKeySpec`, whose Javadoc gives the rationale ("the String class is immutable and there is no way to overwrite its internal value") and whose `clearPassword()` is the zeroing call
- MD5 still works. The JDK's `java.security` restrictions on it - `jdk.certpath.disabledAlgorithms`, `jdk.jar.disabledAlgorithms`, `http.auth.digest.disabledAlgorithms`, `jdk.security.legacyAlgorithms` - cover certificate paths, signed JARs, HTTP Digest and tool warnings, and none of them stops `MessageDigest.getInstance("MD5")` returning a working digest
- A PKCS12 keystore can hold a bare passphrase, not only keys and certificates: JEP 229 records that from JDK 8 it stores secret keys too, and `keytool -importpass` writes one as a `KeyStore.SecretKeyEntry`. PKCS12 has been the default type since JDK 9
- Spring Security's `CompromisedPasswordChecker` with `HaveIBeenPwnedRestApiPasswordChecker` (`@since 6.3`) is picked up automatically as a bean by `DaoAuthenticationProvider`, and rejects known-breached passwords with `CompromisedPasswordException`

## Taint Sinks

`MessageDigest.getInstance("MD5"|"SHA-1"|"SHA-256")` used as a password hash, `NoOpPasswordEncoder`, a stored hash with no `{id}` prefix under a delegating encoder, hardcoded `String password = "..."`, plaintext credentials in `.properties` or a committed profile file, a token compared with `equals()`

## Remediation Steps

- Separate the two cases - Hash what only needs recognising; fetch what must be presented elsewhere
- Replace the encoder - Move to `PasswordEncoderFactories.createDelegatingPasswordEncoder()`, prefix existing stored hashes with their algorithm id, and let `upgradeEncoding` re-encode on successful login
- Check the floor - Confirm Spring Security is at 6.4.5/6.3.9 or later before treating bcrypt verification as sound
- Decide the length policy - Establish what happens to a password over 72 bytes at registration, since encode throws where match does not
- Externalise the rest - Fetch credentials from Secrets Manager, Key Vault or Vault at runtime; on AWS use SDK v2 (`software.amazon.awssdk.services.secretsmanager.SecretsManagerClient`), since v1's `com.amazonaws.services.secretsmanager` reached end of support on 31 December 2025
- Apply char[] where the API allows it - At JDK entry points that hand back an array, clear it with `Arrays.fill` or `PBEKeySpec.clearPassword()`; do not claim it for the Spring encoder path, which takes a `CharSequence`
- Rotate - Treat anything that reached version control or a log as compromised and revoke it before or alongside the cleanup
