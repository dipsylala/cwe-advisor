# CWE-614: Sensitive Cookie Without 'Secure' Flag - PHP

## LLM Guidance

In PHP, cookies set with `setcookie()` or `session_start()` without the `secure` parameter transmit the cookie over HTTP as well as HTTPS, exposing session tokens to network interception. Set the `secure` flag to `true` in `setcookie()` and configure `session.cookie_secure = 1` in `php.ini` or at runtime with `ini_set()`. Combine with `httponly` and `samesite` for defence-in-depth.

## Key Principles

- Pass `secure: true` in the options array to `setcookie()` (PHP 7.3+ syntax)
- Set `session.cookie_secure = 1` in `php.ini` or call `ini_set('session.cookie_secure', '1')` before `session_start()`
- Combine with `httponly: true` and `samesite: 'Strict'` on every sensitive cookie
- Never send sensitive cookies (session ID, authentication tokens) over HTTP
- Enforce HTTPS site-wide to make the `Secure` flag effective

## Remediation Steps

- Find all `setcookie()` calls for session tokens, authentication cookies, and other sensitive values
- Replace legacy five-parameter form with options array and add `'secure' => true, 'httponly' => true, 'samesite' => 'Strict'`
- Add or update `php.ini`: `session.cookie_secure = 1`, `session.cookie_httponly = 1`, `session.cookie_samesite = Strict`
- Alternatively, call `ini_set()` and `session_set_cookie_params()` before `session_start()` if `php.ini` is not configurable
- Verify HTTPS is enforced at the web server level (redirect HTTP → HTTPS)
- Test by loading the page over HTTP and confirming the cookie is not set or transmitted

## Safe Pattern

```php
<?php
// Set session cookie parameters before session_start()
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => true,   // Only send over HTTPS
    'httponly' => true,   // Inaccessible to JavaScript
    'samesite' => 'Strict',
]);
session_start();

// Custom cookie — PHP 7.3+ options array syntax
setcookie('auth_token', $token, [
    'expires'  => time() + 3600,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);

// php.ini equivalents (preferred for consistency)
// session.cookie_secure   = 1
// session.cookie_httponly = 1
// session.cookie_samesite = Strict
```
