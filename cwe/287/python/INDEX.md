# CWE-287: Improper Authentication - Python

## LLM Guidance

In Django applications, Improper Authentication commonly appears as a custom class in `AUTHENTICATION_BACKENDS` whose `authenticate()` looks up a user and returns it without calling `user.check_password()`, or that compares the submitted password to `user.password` directly instead of through Django's password hashers. It also appears with PyJWT, where `jwt.decode()` is called without an explicit `algorithms` allowlist, or with the removed `verify=False` flag / `options={"verify_signature": False}`, letting an unsigned or attacker-chosen-algorithm token pass. Fix by always verifying through `user.check_password()` in custom backends and always passing `algorithms=[...]` to `jwt.decode()`.

## Key Principles

- Custom Django authentication backends must call `user.check_password(password)` (or `django.contrib.auth.hashers.check_password(password, user.password)`) - never compare the submitted password to `user.password` directly or return a user based on lookup alone.
- Rely on Django's configured `PASSWORD_HASHERS` (`Argon2PasswordHasher` via `argon2-cffi` for new projects) instead of a custom hashing routine.
- Always pass an explicit `algorithms=[...]` list to `jwt.decode()`; PyJWT raises `DecodeError` if `algorithms` is omitted while signature verification is enabled, but state it in code rather than leaning on that as the only guard.
- Never call `jwt.decode()` with `options={"verify_signature": False}` (or the `verify=False` flag, removed in PyJWT 2.0.0) outside of explicitly non-trust-boundary debugging - both skip signature verification entirely.
- `ModelBackend` already equalises the two branches by running the default hasher on the miss - inline in the `DoesNotExist` branch before Django 6.1, through `check_password_with_timing_attack_mitigation()` from 6.1 - so a timing finding against the stock backend is a false positive. A custom backend does not inherit it: hash and discard in that branch before returning `None`, against the *configured* user model, as Django's own code does (`UserModel()`, or `get_user_model()()`). The binding decides that, not the name - `User = get_user_model()` is the configured model and is correct, `User` from `django.contrib.auth.models` is not - so check the import before treating a `User()` call as the defect.
- In a Flask login view, `if user and user.check_password(...)` short-circuits and never reaches the hasher for an unknown address; verify against a `DUMMY_HASH` with `check_password_hash()` in the `else` branch instead, and use it for a user row with no stored hash as well.
- Generate that dummy once with `generate_password_hash()` using the same method and parameters as the stored hashes and paste it in as a constant - `check_password_hash()` reads both out of the hash string it is given, so a scrypt dummy in front of pbkdf2 user hashes restores the gap it was added to close - Werkzeug's default became `scrypt` in 3.0.0 (`pbkdf2` before), which is where that mismatch usually comes from.
- Return `None` from a custom backend's `authenticate()` on any failure so Django's `authenticate()` falls through to the next configured backend instead of raising and short-circuiting.
- Django hashes new and rehashed passwords with the *first* `PASSWORD_HASHERS` entry and verifies against whichever listed hasher matches the stored hash, so changing algorithm means moving it to the front - not an instruction to order by strength, which would flag the shipped default, `PBKDF2PasswordHasher` first and `Argon2PasswordHasher` third.
- Django's `django.contrib.auth.login()` calls `request.session.cycle_key()`, which keeps the session data and issues a new key; a login path that writes `request.session['user_id']` directly skips it
- Flask-Login's `login_user()` has no session identifier to rotate on stock Flask, whose session is a signed client-side cookie - set `SESSION_PROTECTION = 'strong'` (binds the session to a hash of the client IP and user agent, deleting it on a mismatch) with `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SECURE` and `SESSION_COOKIE_SAMESITE`, and never write to `session[...]` before `login_user()`, which would carry pre-login state into the authenticated session; a true identifier rotation exists only behind a server-side session store

## Taint Sinks

Direct `user.password` comparison bypassing `check_password()`, `jwt.decode()` with `options={"verify_signature": False}` or missing `algorithms`

## Remediation Steps

- Locate - Find `AUTHENTICATION_BACKENDS` entries and their `authenticate()` methods, and `jwt.decode()` call sites
- Trace data flow - Follow the submitted password into the backend's `authenticate()`, and the token from the `Authorization` header into `jwt.decode()`
- Replace the unsafe pattern - Add `user.check_password(password)` to any backend missing it; add `algorithms=[...]` to any `jwt.decode()` call missing it
- Bind, encode, validate, or authorize - Confirm the `algorithms` list matches only the algorithm(s) the issuer actually signs with (e.g. `algorithms=["HS256"]`), not a list mixing HMAC and RSA algorithms unless both are genuinely issued
- Break taint after allowlist validation - Trust only the dict returned by a `jwt.decode()` call that succeeded with signature verification enabled; do not read claims from a debug-only unverified decode used elsewhere in the same path
- Harden configuration - Load JWT signing keys from environment variables or a secret manager, and confirm the first `PASSWORD_HASHERS` entry is the algorithm new passwords should use
- Test - Time a right password, a wrong password, and an unknown account and assert all three are within noise of each other and no failure returns a `500`; write a test with an incorrect password (expect `authenticate()` returns `None`) and a forged token with `alg: none` or a mismatched algorithm (expect `jwt.decode()` to raise `InvalidAlgorithmError`/`DecodeError`)
