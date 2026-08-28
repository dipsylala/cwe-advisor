# CWE-287: Improper Authentication - Python

## LLM Guidance

In Django applications, Improper Authentication commonly appears as a custom class in `AUTHENTICATION_BACKENDS` whose `authenticate()` looks up a user and returns it without calling `user.check_password()`, or that compares the submitted password to `user.password` directly instead of through Django's password hashers. It also appears with PyJWT, where `jwt.decode()` is called without an explicit `algorithms` allowlist, or with the removed `verify=False` flag / `options={"verify_signature": False}`, letting an unsigned or attacker-chosen-algorithm token pass. Fix by always verifying through `user.check_password()` in custom backends and always passing `algorithms=[...]` to `jwt.decode()`.

## Key Principles

- Custom Django authentication backends must call `user.check_password(password)` (or `django.contrib.auth.hashers.check_password(password, user.password)`) - never compare the submitted password to `user.password` directly or return a user based on lookup alone.
- Rely on Django's configured `PASSWORD_HASHERS` (PBKDF2 by default, or `Argon2PasswordHasher` via the `argon2-cffi` package for new projects) instead of a custom hashing routine.
- Always pass an explicit `algorithms=[...]` list to `jwt.decode()`; PyJWT raises `DecodeError` if `algorithms` is omitted while signature verification is enabled, but state the expected algorithm in code rather than relying on that as the only guard.
- Never call `jwt.decode()` with `options={"verify_signature": False}` (or the removed `verify=False` flag from PyJWT 1.x) outside of explicitly non-trust-boundary debugging - both skip signature verification entirely.
- `ModelBackend` already equalises the two branches through `check_password_with_timing_attack_mitigation()`, so a timing finding against the stock backend is a false positive; a custom backend does not inherit it - call `User().set_password(password)` in the `User.DoesNotExist` branch and discard the result before returning `None`, or an unknown address is answered in 0.2 ms against 916 ms for a wrong password.
- In a Flask login view, `if user and user.check_password(...)` short-circuits and never reaches the hasher for an unknown address; verify against a `DUMMY_HASH` with `check_password_hash()` in the `else` branch instead, and use it for a user row with no stored hash as well.
- Generate that dummy once with `generate_password_hash()` using the same method and parameters as the stored hashes and paste it in as a constant - `check_password_hash()` reads both out of the hash string it is given, so a scrypt dummy standing in front of pbkdf2 user hashes restores the gap it was added to close, and `''` or a malformed string returns in microseconds.
- Return `None` from a custom backend's `authenticate()` on any failure so Django's `authenticate()` falls through to the next configured backend instead of raising and short-circuiting.
- Keep `PASSWORD_HASHERS` ordered with the strongest hasher first; Django rehashes automatically to the first entry on the next successful login.
- Django's `django.contrib.auth.login()` calls `request.session.cycle_key()`, which keeps the session data and issues a new key; a login path that writes `request.session['user_id']` directly skips it
- Flask-Login's `login_user()` has no session identifier to rotate on stock Flask, whose session is a signed client-side cookie - set `SESSION_PROTECTION = 'strong'` (binds the session to the client IP and user agent) along with `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SECURE`, and `SESSION_COOKIE_SAMESITE`, and never write to `session[...]` before calling `login_user()`, which would carry pre-login state into the authenticated session; a true identifier rotation exists only behind a server-side session store

## Taint Sinks

Direct `user.password` comparison bypassing `check_password()`, `jwt.decode()` with `options={"verify_signature": False}` or missing `algorithms`

## Remediation Steps

- Locate - Find `AUTHENTICATION_BACKENDS` entries and their `authenticate()` methods, and `jwt.decode()` call sites
- Trace data flow - Follow the submitted password into the backend's `authenticate()`, and the token from the `Authorization` header into `jwt.decode()`
- Replace the unsafe pattern - Add `user.check_password(password)` to any backend missing it; add `algorithms=[...]` to any `jwt.decode()` call missing it
- Bind, encode, validate, or authorize - Confirm the `algorithms` list matches only the algorithm(s) the issuer actually signs with (e.g. `algorithms=["HS256"]`), not a list mixing HMAC and RSA algorithms unless both are genuinely issued
- Break taint after allowlist validation - Trust only the dict returned by a `jwt.decode()` call that succeeded with signature verification enabled; do not read claims from a debug-only unverified decode used elsewhere in the same path
- Harden configuration - Load JWT signing keys from environment variables or a secret manager, and confirm `PASSWORD_HASHERS` lists a strong hasher first
- Test - Time a right password, a wrong password, and an unknown account and assert all three are within noise of each other and no failure returns a `500`; write a test with an incorrect password (expect `authenticate()` returns `None`) and a forged token with `alg: none` or a mismatched algorithm (expect `jwt.decode()` to raise `InvalidAlgorithmError`/`DecodeError`)
