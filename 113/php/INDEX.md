# CWE-113: HTTP Response Splitting - PHP

## LLM Guidance

HTTP Response Splitting in PHP occurs when user-supplied values are passed to `header()` without stripping CRLF characters. PHP 7.4+ raises an error and suppresses headers containing `\n` or `\r\n` in native `header()` calls, but older versions and some frameworks do not provide this protection. Even in PHP 7.4+, percent-encoded variants (`%0a`, `%0d`) may still reach `header()` after URL decoding in redirect flows. Always sanitize user input before it enters any `header()` call and validate redirect destinations against an allowlist.

## Key Principles

- Strip `\r`, `\n`, and their percent-encoded forms (`%0a`, `%0d`) from all user input before passing it to `header()`
- Also strip Unicode line terminators: U+0085, U+2028, U+2029
- Never use `header('Location: ' . $userInput)` without validating the URL against an allowlist of permitted destinations
- Prefer `wp_redirect()` / framework redirect helpers that perform URL validation over raw `header()` calls
- Use `setcookie()` instead of `header('Set-Cookie: ...')` to avoid manual cookie header construction

## Remediation Steps

- Locate `header('Location: ' . $var)` patterns where `$var` derives from user input
- Validate redirect URLs — confirm they match a relative path pattern or an allowed origin allowlist
- Strip CRLF characters and percent-encoded variants before any `header()` call: remove `\r`, `\n`, `%0a`, `%0d`, and Unicode line terminators
- Replace manual `header('Set-Cookie: ...')` construction with `setcookie()` which handles encoding automatically
- For `Content-Disposition`, sanitize the filename component with `basename()` and strip CRLF
- Test with `%0d%0aX-Injected: evil` appended to redirect parameters

## Safe Pattern

```php
<?php
function sanitizeHeaderValue(string $value): string {
    // Remove CRLF, percent-encoded variants, and Unicode line terminators
    return preg_replace('/[\r\n\x{0085}\x{2028}\x{2029}]|%0[aAdD]/u', '', $value);
}

$allowedPaths = ['/dashboard', '/profile', '/home'];

// Safe redirect with allowlist
$next = $_GET['next'] ?? '/home';
if (!in_array($next, $allowedPaths, true)) {
    $next = '/home';
}
header('Location: ' . $next);
exit;

// Safe cookie — use setcookie() not header()
setcookie('pref', sanitizeHeaderValue($_GET['theme'] ?? 'light'), [
    'httponly' => true,
    'samesite' => 'Strict',
    'secure'   => true,
]);

// Safe Content-Disposition for downloads
$filename = sanitizeHeaderValue(basename($_GET['file'] ?? 'download'));
header('Content-Disposition: attachment; filename="' . $filename . '"');
```
