# CWE-94: Code Injection - PHP

## LLM Guidance

Code injection in PHP most commonly occurs via `eval()`, the `preg_replace()` `/e` modifier (removed in PHP 7), `create_function()` (removed in PHP 8), `assert()` with a string argument, or `include`/`require` of a user-controlled path. `eval()` executes arbitrary PHP, giving an attacker full control of the server. Replace all dynamic code execution with static logic; there is no safe way to sandbox `eval()` in PHP.

## Key Principles

- Remove all `eval()` calls; there is no sanitization that makes `eval($userInput)` safe
- Replace `assert($stringExpression)` with direct boolean assertions — `assert()` with a string argument behaves like `eval()` in PHP 7 and earlier
- Never use `include`/`require` with user-controlled paths — use an allowlist of permitted filenames
- Replace dynamic dispatch patterns with `match` expressions or lookup arrays of callable functions
- Disable `allow_url_include` and `allow_url_fopen` in `php.ini` to block remote file inclusion

## Remediation Steps

- Search for `eval(`, `assert("`, `preg_replace(.*/e`, `create_function(` and remove each one
- Replace `eval()` with a `match` statement, `switch`, or an array of named callables keyed by allowlisted identifiers
- For `include`/`require` with variable paths, replace with an allowlist: `$allowed = ['home', 'about']; if (in_array($page, $allowed, true)) include __DIR__ . "/pages/{$page}.php";`
- Set `assert.active = Off` in `php.ini` or `ini_set('assert.active', '0')` to disable string-based assertions
- Enable `display_errors = Off` in production so error messages don't reveal code-injection paths
- Test by submitting `system('id')` or `phpinfo()` as input values and confirming they are not executed

## Safe Pattern

```php
<?php
// SAFE: replace eval() with a lookup of predefined callables
$operations = [
    'double' => fn(float $x): float => $x * 2,
    'square' => fn(float $x): float => $x ** 2,
    'negate' => fn(float $x): float => -$x,
];

$opName = $_GET['op'] ?? '';
if (!isset($operations[$opName])) {
    http_response_code(400);
    exit('Invalid operation');
}
$result = $operations[$opName](42.0);

// SAFE: allowlist-controlled include
$allowedPages = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? 'home';
if (!in_array($page, $allowedPages, true)) {
    $page = 'home';
}
include __DIR__ . '/pages/' . $page . '.php';
```
