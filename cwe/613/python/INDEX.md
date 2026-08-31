# CWE-613: Insufficient Session Expiration - Python

## LLM Guidance

Django's session cookie defaults to `SESSION_COOKIE_AGE` of 1,209,600 seconds (two weeks) unless `SESSION_EXPIRE_AT_BROWSER_CLOSE` is set; Flask's session is a browser-session cookie with no expiry at all unless `session.permanent = True` is set explicitly, in which case `PERMANENT_SESSION_LIFETIME` (31 days by default) applies. A hand-issued JWT via PyJWT has no framework default to lean on either way: `exp` is a plain dict key the caller adds, `jwt.decode()` does check it by default and raises `ExpiredSignatureError`, but that check can be turned off entirely with the real, documented `options={"verify_exp": False}` - a footgun worth searching for on its own. Django REST Framework's SimpleJWT is the one library here with sane defaults out of the box: access tokens expire in 5 minutes.

## Key Principles

- Django's `SESSION_COOKIE_AGE` defaults to 1,209,600 seconds (two weeks); `SESSION_EXPIRE_AT_BROWSER_CLOSE` (default `False`) is the separate toggle for session-only cookies, and `SESSION_SAVE_EVERY_REQUEST` (default `False`) is what makes the timeout slide on activity rather than counting from first login
- Flask's session has no expiry at all unless `session.permanent = True` is set at the point the session is created - only then does `PERMANENT_SESSION_LIFETIME` (31 days by default) apply, and `SESSION_REFRESH_EACH_REQUEST` (default `True`) resends the cookie each response to slide that window
- PyJWT enforces no maximum lifetime - `exp` is a plain dict key (a Unix timestamp or a `datetime`) the caller adds to the payload passed to `jwt.encode()`, so a token minted without one never expires
- `jwt.decode()` validates `exp` by default and raises `ExpiredSignatureError` once it has passed - but `options={"verify_exp": False}` is a real, documented way to disable that check, so search for it explicitly rather than assuming expiration validation is always on wherever `decode()` is called
- Django REST Framework's SimpleJWT ships sane defaults - `ACCESS_TOKEN_LIFETIME` of 5 minutes, `REFRESH_TOKEN_LIFETIME` of 1 day - and its own rotation-plus-blacklist feature (`ROTATE_REFRESH_TOKENS`, `BLACKLIST_AFTER_ROTATION`) is the built-in answer for pre-expiry revocation, but the blacklist requires adding `rest_framework_simplejwt.token_blacklist` to `INSTALLED_APPS` - it does nothing silently if that app isn't installed
- For a hand-issued PyJWT token with no framework around it, pre-expiry revocation needs its own `jti`-keyed store, since PyJWT itself tracks nothing after signing

## Taint Sinks

`jwt.encode()` with a payload missing `exp`, `jwt.decode(..., options={"verify_exp": False})`, Django `SESSION_COOKIE_AGE` set excessively long, Flask `session.permanent = True` with no `PERMANENT_SESSION_LIFETIME` override, SimpleJWT configured with `ROTATE_REFRESH_TOKENS = True` but no `token_blacklist` app installed

## Remediation Steps

- Locate - find `jwt.encode()`/`jwt.decode()` calls, Django `SESSION_COOKIE_AGE`/`SESSION_EXPIRE_AT_BROWSER_CLOSE` settings, Flask `PERMANENT_SESSION_LIFETIME` and `session.permanent` usage, and SimpleJWT's `ACCESS_TOKEN_LIFETIME`/`REFRESH_TOKEN_LIFETIME`
- Trace what the session or token authorizes, to size the lifetime to the risk
- Identify the unsafe pattern - a JWT payload missing `exp`, a `verify_exp: False` override, or a session lifetime left at a framework default nobody chose deliberately
- Replace with an explicit `exp` and a deliberately-chosen session/token lifetime
- Bind, encode, validate, or authorize - install `token_blacklist` and enable `ROTATE_REFRESH_TOKENS`/`BLACKLIST_AFTER_ROTATION` for SimpleJWT, or add a `jti`-keyed store for a hand-issued PyJWT token
- Harden configuration - remove any `verify_exp: False` override that isn't paired with the caller doing its own separate expiration check
- Test - confirm a token or session issued before the fix is rejected once its new, shorter lifetime passes, and that a blacklisted or denylisted token is rejected on the very next request
