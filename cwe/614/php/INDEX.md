# CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute - PHP

## LLM Guidance

In PHP, cookies set with `setcookie()` or `session_start()` without the `secure` parameter transmit the cookie over HTTP as well as HTTPS, exposing session tokens to network interception. Set the `secure` flag to `true` in `setcookie()` and configure `session.cookie_secure = 1` in `php.ini` or at runtime with `ini_set()`. Combine with `httponly` and `samesite` for defence-in-depth.

## Key Principles

- Pass `secure: true` in the options array to `setcookie()` (PHP 7.3+ syntax)
- Set `session.cookie_secure = 1` in `php.ini` or call `ini_set('session.cookie_secure', '1')` before `session_start()`
- Combine with `httponly: true` and `samesite: 'Strict'` on every sensitive cookie
- Never send sensitive cookies (session ID, authentication tokens) over HTTP
- Enforce HTTPS site-wide to make the `Secure` flag effective
- Set the parameters before the session starts (`session_set_cookie_params([...])` ahead of `session_start()`), or `PHPSESSID` is issued with the ini defaults
- Set `samesite` in the same call, choosing `Lax` or `Strict` per flow, and set `session.cookie_secure=1` in php.ini so a code path that starts a session without the call still gets it

## Taint Sinks

`setcookie()` without `secure` option, `session_start()` with `session.cookie_secure` unset, `session_set_cookie_params()` without `secure`

## Remediation Steps

- Find all `setcookie()` calls for session tokens, authentication cookies, and other sensitive values
- Replace legacy five-parameter form with options array and add `'secure' => true, 'httponly' => true, 'samesite' => 'Strict'`
- Add or update `php.ini`: `session.cookie_secure = 1`, `session.cookie_httponly = 1`, `session.cookie_samesite = Strict`
- Alternatively, call `ini_set()` and `session_set_cookie_params()` before `session_start()` if `php.ini` is not configurable
- Verify HTTPS is enforced at the web server level (redirect HTTP → HTTPS)
- Test by loading the page over HTTP and confirming the cookie is not set or transmitted
