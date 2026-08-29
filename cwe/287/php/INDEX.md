# CWE-287: Improper Authentication - PHP

## LLM Guidance

In PHP applications, Improper Authentication commonly appears as credential checks that compare passwords with `==`/`!=` or a raw hash function instead of `password_verify()`, which is both timing-unsafe and accepts weak or unsalted hashing schemes. It also appears with `firebase/php-jwt`, where `JWT::decode()` is called using the removed array-of-algorithms form or without a bound algorithm, leaving the token's own `alg` header able to influence which algorithm is used to verify it. Fix by verifying credentials with `password_verify()` and, on `firebase/php-jwt` 6.x+, wrapping the signing key in a `Firebase\JWT\Key` object that binds one explicit algorithm to that key.

## Key Principles

- Verify credentials with `password_verify($password, $storedHash)`; never compare hashes with `==`/`!=` (use `hash_equals()` if a non-`password_verify` comparison is ever required, to avoid timing attacks), and never store or compare plaintext passwords.
- Call `password_verify()` on the lookup-miss branch too, against a `DUMMY_HASH` constant generated once with `password_hash()` at the same algorithm and cost as the stored hashes - returning as soon as the user row is `null` answers without ever hashing, where a wrong password pays the full cost.
- Use the same dummy when the stored hash column is empty (an SSO-only account), or that row becomes the fast case instead of the missing one.
- Hash new or changed passwords with `password_hash($password, PASSWORD_DEFAULT)` (or `PASSWORD_ARGON2ID`), and rehash on login when `password_needs_rehash()` reports the stored hash uses outdated parameters.
- With `firebase/php-jwt` 6.x+, call `JWT::decode($jwt, new Key($key, 'HS256'))` (or an array of `Key` objects keyed by `kid` for key rotation) - this binds one explicit algorithm to the key, so the token's own `alg` header cannot select a different algorithm.
- The `firebase/php-jwt` array-of-algorithms call form (`JWT::decode($jwt, $key, ['HS256'])`) was removed in 6.0.0, not deprecated: the third parameter is now `?stdClass &$headers`, so passing an array raises a `TypeError` rather than a notice. Current release is 7.1.0.
- Let `JWT::decode()` throw on any algorithm mismatch or `alg: none` header (`UnexpectedValueException`/`SignatureInvalidException`) - catch it only to reject the request, never to fall back to unverified data.
- Store JWT signing secrets and password pepper values outside source control (environment variables or a secret manager), not hardcoded in the codebase.
- Call `session_regenerate_id()` at successful login so the pre-authentication identifier stops being the authenticated one. Leave `$delete_old_session` at its `false` default unless the trade-off has been considered: php.net says "You should not delete old session if you need to avoid races caused by deletion or detect/avoid session hijack attacks", and its Warning block asks instead for a destroy timestamp on the old session plus controlled access to the old ID, because "Immediate session data deletion disables session hijack attack detection and prevention also"
- Laravel's `Auth::attempt()` verifies the password with the configured hasher and regenerates the session on success (a hand-rolled login that writes the user id into the session directly does neither), and it closes the login timing channel itself: the whole attempt runs inside an `Illuminate\Support\Timebox` that pads every failing path to `timeboxDuration`, 200000 microseconds by default, and is short-circuited only by the `returnEarly()` on success
- So do not add a dummy `Hash::check` on the no-such-user branch of a current Laravel - it buys a second verification inside a call that is already padded. The Timebox has wrapped `hasValidCredentials()` since 9.32.0 (CVE-2022-40482) and was moved out to wrap `attempt()` entirely, covering the `retrieveByCredentials()` lookup too, in 12.14.0 and 11.45.0; below those the provider lookup sits outside the padded region

## Taint Sinks

`==`/`!=` password comparison, `JWT::decode($jwt, $key, $algs)` array-of-algorithms form (`firebase/php-jwt` before 6.0)

## Remediation Steps

- Locate - Find password comparison code in login handlers and `JWT::decode()`/`JWT::encode()` call sites
- Trace data flow - Follow the submitted password into the comparison, and the bearer token from the `Authorization` header into `JWT::decode()`
- Replace the unsafe pattern - Change `==`/raw hash comparisons to `password_verify()`; change the legacy `JWT::decode($jwt, $key, $algs)` form to `JWT::decode($jwt, new Key($key, 'HS256'))`
- Bind, encode, validate, or authorize - Ensure the algorithm passed to `Key` matches exactly what the issuer signs with; do not list multiple algorithms unless the issuer genuinely uses more than one key/algorithm pair
- Break taint after allowlist validation - Trust only the `stdClass` payload returned after `JWT::decode()` succeeds; a caught exception must reject the request, not fall back to unverified data
- Harden configuration - Confirm `password_hash()` uses `PASSWORD_ARGON2ID` or `PASSWORD_DEFAULT` (not MD5/SHA1), and JWT secrets are loaded from environment configuration
- Test - Time a right password, a wrong password, and an unknown address and assert all three are within noise of each other; write a test with an incorrect password (expect `password_verify()` to return false) and a forged token with `alg: none` or a mismatched algorithm (expect `JWT::decode()` to throw)
