# CWE-287: Improper Authentication - PHP

## LLM Guidance

In PHP applications, Improper Authentication commonly appears as credential checks that compare passwords with `==`/`!=` or a raw hash function instead of `password_verify()`, which is both timing-unsafe and accepts weak or unsalted hashing schemes. It also appears with `firebase/php-jwt`, where `JWT::decode()` is called using the deprecated array-of-algorithms form or without a bound algorithm, leaving the token's own `alg` header able to influence which algorithm is used to verify it. Fix by verifying credentials with `password_verify()` and, on `firebase/php-jwt` 6.x+, wrapping the signing key in a `Firebase\JWT\Key` object that binds one explicit algorithm to that key.

## Key Principles

- Verify credentials with `password_verify($password, $storedHash)`; never compare hashes with `==`/`!=` (use `hash_equals()` if a non-`password_verify` comparison is ever required, to avoid timing attacks), and never store or compare plaintext passwords.
- Call `password_verify()` on the lookup-miss branch too, against a `DUMMY_HASH` constant generated once with `password_hash()` at the same algorithm and cost as the stored hashes - returning as soon as the user row is `null` answers in 0.0004 ms against 218 ms for a wrong password, and `''` or a truncated placeholder returns without verifying.
- Use the same dummy when the stored hash column is empty (an SSO-only account), or that row becomes the fast case instead of the missing one.
- Hash new or changed passwords with `password_hash($password, PASSWORD_DEFAULT)` (or `PASSWORD_ARGON2ID`), and rehash on login when `password_needs_rehash()` reports the stored hash uses outdated parameters.
- With `firebase/php-jwt` 6.x+, call `JWT::decode($jwt, new Key($key, 'HS256'))` (or an array of `Key` objects keyed by `kid` for key rotation) - this binds one explicit algorithm to the key, so the token's own `alg` header cannot select a different algorithm.
- Do not use the deprecated `firebase/php-jwt` array-of-algorithms call form (`JWT::decode($jwt, $key, ['HS256'])`, library versions before 6.0) in new or updated code; upgrade to the `Key`-object form.
- Let `JWT::decode()` throw on any algorithm mismatch or `alg: none` header (`UnexpectedValueException`/`SignatureInvalidException`) - catch it only to reject the request, never to fall back to unverified data.
- Store JWT signing secrets and password pepper values outside source control (environment variables or a secret manager), not hardcoded in the codebase.
- Call `session_regenerate_id(true)` - the default `false` keeps the old session file alive with its current contents, so the pre-authentication identifier remains a valid session
- Laravel's `Auth::attempt()` verifies the password with the configured hasher and migrates the session on success (a hand-rolled login that writes the user id into the session directly does neither), but it does not close the timing channel: `SessionGuard::hasValidCredentials()` short-circuits and never reaches the hasher when the provider finds no user
- On a failed `Auth::attempt()` where `Auth::guard()->getLastAttempted()` returns `null` - exactly the no-such-user branch - run `Hash::check($password, DUMMY_HASH)`; do it only on that branch, or a wrong password pays for two verifications and the channel reopens pointing the other way

## Taint Sinks

`==`/`!=` password comparison, legacy `JWT::decode($jwt, $key, $algs)` array-of-algorithms form

## Remediation Steps

- Locate - Find password comparison code in login handlers and `JWT::decode()`/`JWT::encode()` call sites
- Trace data flow - Follow the submitted password into the comparison, and the bearer token from the `Authorization` header into `JWT::decode()`
- Replace the unsafe pattern - Change `==`/raw hash comparisons to `password_verify()`; change the legacy `JWT::decode($jwt, $key, $algs)` form to `JWT::decode($jwt, new Key($key, 'HS256'))`
- Bind, encode, validate, or authorize - Ensure the algorithm passed to `Key` matches exactly what the issuer signs with; do not list multiple algorithms unless the issuer genuinely uses more than one key/algorithm pair
- Break taint after allowlist validation - Trust only the `stdClass` payload returned after `JWT::decode()` succeeds; a caught exception must reject the request, not fall back to unverified data
- Harden configuration - Confirm `password_hash()` uses `PASSWORD_ARGON2ID` or `PASSWORD_DEFAULT` (not MD5/SHA1), and JWT secrets are loaded from environment configuration
- Test - Time a right password, a wrong password, and an unknown address and assert all three are within noise of each other; write a test with an incorrect password (expect `password_verify()` to return false) and a forged token with `alg: none` or a mismatched algorithm (expect `JWT::decode()` to throw)
