# CWE-287: Improper Authentication - Python

## LLM Guidance

In Django applications, Improper Authentication commonly appears as a custom class in `AUTHENTICATION_BACKENDS` whose `authenticate()` looks up a user and returns it without calling `user.check_password()`, or that compares the submitted password to `user.password` directly instead of through Django's password hashers. It also appears with PyJWT, where `jwt.decode()` is called without an explicit `algorithms` allowlist, or with the removed `verify=False` flag / `options={"verify_signature": False}`, letting an unsigned or attacker-chosen-algorithm token pass. Fix by always verifying through `user.check_password()` in custom backends and always passing `algorithms=[...]` to `jwt.decode()`.

## Key Principles

- Custom Django authentication backends must call `user.check_password(password)` (or `django.contrib.auth.hashers.check_password(password, user.password)`) - never compare the submitted password to `user.password` directly or return a user based on lookup alone.
- Rely on Django's configured `PASSWORD_HASHERS` (PBKDF2 by default, or `Argon2PasswordHasher` via the `argon2-cffi` package for new projects) instead of a custom hashing routine.
- Always pass an explicit `algorithms=[...]` list to `jwt.decode()`; PyJWT raises `DecodeError` if `algorithms` is omitted while signature verification is enabled, but state the expected algorithm in code rather than relying on that as the only guard.
- Never call `jwt.decode()` with `options={"verify_signature": False}` (or the removed `verify=False` flag from PyJWT 1.x) outside of explicitly non-trust-boundary debugging - both skip signature verification entirely.
- Return `None` from a custom backend's `authenticate()` on any failure so Django's `authenticate()` falls through to the next configured backend instead of raising and short-circuiting.
- Keep `PASSWORD_HASHERS` ordered with the strongest hasher first; Django rehashes automatically to the first entry on the next successful login.

## Remediation Steps

- Locate - Find `AUTHENTICATION_BACKENDS` entries and their `authenticate()` methods, and `jwt.decode()` call sites
- Trace data flow - Follow the submitted password into the backend's `authenticate()`, and the token from the `Authorization` header into `jwt.decode()`
- Replace the unsafe pattern - Add `user.check_password(password)` to any backend missing it; add `algorithms=[...]` to any `jwt.decode()` call missing it
- Bind, encode, validate, or authorize - Confirm the `algorithms` list matches only the algorithm(s) the issuer actually signs with (e.g. `algorithms=["HS256"]`), not a list mixing HMAC and RSA algorithms unless both are genuinely issued
- Break taint after allowlist validation - Trust only the dict returned by a `jwt.decode()` call that succeeded with signature verification enabled; do not read claims from a debug-only unverified decode used elsewhere in the same path
- Harden configuration - Load JWT signing keys from environment variables or a secret manager, and confirm `PASSWORD_HASHERS` lists a strong hasher first
- Test - Write a test with an incorrect password (expect `authenticate()` returns `None`) and a forged token with `alg: none` or a mismatched algorithm (expect `jwt.decode()` to raise `InvalidAlgorithmError`/`DecodeError`)

## Safe Pattern

```python
# SAFE: Django custom backend verifies the password hash
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

class EmailAuthBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        User = get_user_model()
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            return None

        if user.check_password(password) and user.is_active:
            return user
        return None

    def get_user(self, user_id):
        User = get_user_model()
        return User.objects.filter(pk=user_id).first()

# SAFE: PyJWT decode with an explicit algorithm allowlist
import jwt

def verify_token(token: str) -> dict:
    return jwt.decode(token, key=SIGNING_KEY, algorithms=["HS256"])
```
