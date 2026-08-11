# CWE-287: Improper Authentication - PHP

## LLM Guidance

In PHP applications, Improper Authentication commonly appears as credential checks that compare passwords with `==`/`!=` or a raw hash function instead of `password_verify()`, which is both timing-unsafe and accepts weak or unsalted hashing schemes. It also appears with `firebase/php-jwt`, where `JWT::decode()` is called using the deprecated array-of-algorithms form or without a bound algorithm, leaving the token's own `alg` header able to influence which algorithm is used to verify it. Fix by verifying credentials with `password_verify()` and, on `firebase/php-jwt` 6.x+, wrapping the signing key in a `Firebase\JWT\Key` object that binds one explicit algorithm to that key.

## Key Principles

- Verify credentials with `password_verify($password, $storedHash)`; never compare hashes with `==`/`!=` (use `hash_equals()` if a non-`password_verify` comparison is ever required, to avoid timing attacks), and never store or compare plaintext passwords.
- Hash new or changed passwords with `password_hash($password, PASSWORD_DEFAULT)` (or `PASSWORD_ARGON2ID`), and rehash on login when `password_needs_rehash()` reports the stored hash uses outdated parameters.
- With `firebase/php-jwt` 6.x+, call `JWT::decode($jwt, new Key($key, 'HS256'))` (or an array of `Key` objects keyed by `kid` for key rotation) - this binds one explicit algorithm to the key, so the token's own `alg` header cannot select a different algorithm.
- Do not use the deprecated `firebase/php-jwt` array-of-algorithms call form (`JWT::decode($jwt, $key, ['HS256'])`, library versions before 6.0) in new or updated code; upgrade to the `Key`-object form.
- Let `JWT::decode()` throw on any algorithm mismatch or `alg: none` header (`UnexpectedValueException`/`SignatureInvalidException`) - catch it only to reject the request, never to fall back to unverified data.
- Store JWT signing secrets and password pepper values outside source control (environment variables or a secret manager), not hardcoded in the codebase.

## Remediation Steps

- Locate - Find password comparison code in login handlers and `JWT::decode()`/`JWT::encode()` call sites
- Trace data flow - Follow the submitted password into the comparison, and the bearer token from the `Authorization` header into `JWT::decode()`
- Replace the unsafe pattern - Change `==`/raw hash comparisons to `password_verify()`; change the legacy `JWT::decode($jwt, $key, $algs)` form to `JWT::decode($jwt, new Key($key, 'HS256'))`
- Bind, encode, validate, or authorize - Ensure the algorithm passed to `Key` matches exactly what the issuer signs with; do not list multiple algorithms unless the issuer genuinely uses more than one key/algorithm pair
- Break taint after allowlist validation - Trust only the `stdClass` payload returned after `JWT::decode()` succeeds; a caught exception must reject the request, not fall back to unverified data
- Harden configuration - Confirm `password_hash()` uses `PASSWORD_ARGON2ID` or `PASSWORD_DEFAULT` (not MD5/SHA1), and JWT secrets are loaded from environment configuration
- Test - Write a test with an incorrect password (expect `password_verify()` to return false) and a forged token with `alg: none` or a mismatched algorithm (expect `JWT::decode()` to throw)

## Safe Pattern

```php
<?php
// SAFE: verify credentials with password_verify(), never a raw comparison
if (!password_verify($submittedPassword, $user['password_hash'])) {
    throw new AuthenticationException('Invalid credentials');
}
if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
    $newHash = password_hash($submittedPassword, PASSWORD_DEFAULT);
    // persist $newHash for $user
}

// SAFE: firebase/php-jwt 6.x - Key binds one explicit algorithm to the key
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$decoded = JWT::decode($jwtToken, new Key($signingKey, 'HS256'));
$userId = $decoded->sub;
```
