# CWE-94: Improper Control of Generation of Code ('Code Injection') - PHP

## LLM Guidance

Code injection in PHP most commonly occurs via `eval()`, the `preg_replace()` `/e` modifier (removed in PHP 7), `create_function()` (removed in PHP 8), `assert()` with a string argument, or `include`/`require` of a user-controlled path. `eval()` executes arbitrary PHP, giving an attacker full control of the server. Replace all dynamic code execution with static logic; there is no safe way to sandbox `eval()` in PHP.

## Key Principles

- Remove all `eval()` calls; there is no sanitization that makes `eval($userInput)` safe
- Replace `assert($stringExpression)` with direct boolean assertions - `assert()` with a string argument behaves like `eval()` in PHP 7 and earlier, but stopped evaluating in PHP 8.0, where a non-empty string is simply truthy; on a PHP 8 target the finding is not exploitable and what remains is an assertion that has never tested anything
- Never use `include`/`require` with user-controlled paths - use an allowlist of permitted filenames
- Replace dynamic dispatch patterns with `match` expressions or lookup arrays of callable functions
- Confirm rather than assume the include hardening: `allow_url_include` already defaults to `0` and
  has been deprecated since PHP 7.4, so setting it is usually recording intent rather than closing
  anything, while `allow_url_fopen` defaults to `1` and is the one likely to need changing. Neither
  affects a *local* file inclusion through the same sink, which is the more common finding.
  `disable_functions` cannot close `eval` because `eval` is a language construct rather than a
  function, so listing it there records a control that was never applied - and the manual warns the
  directive "can be circumvented and should not be considered a sufficient security measure"; `disable_functions` cannot close `eval` because `eval` is a language construct rather than a function, so listing it there records a control that was never applied - the directive is still worth setting for `system`, `exec`, `passthru`, `proc_open` and `popen`

## Taint Sinks

`eval()`, `assert($string)`, `preg_replace()` with `/e` modifier, `create_function()`, `include`/`require` with user-controlled path

## Remediation Steps

- Search for `eval(`, `assert("`, `preg_replace(.*/e`, `create_function(` and remove each one - the
  vendor's named replacements are `preg_replace_callback()` for the `/e` modifier and an anonymous
  function for `create_function()`, so these are usually rewrites rather than deletions
- Replace `eval()` with a `match` statement, `switch`, or an array of named callables keyed by allowlisted identifiers
- For `include`/`require` with variable paths, replace with an allowlist: `$allowed = ['home', 'about']; if (in_array($page, $allowed, true)) include __DIR__ . "/pages/{$page}.php";`
- Establish the PHP version before triaging `assert($string)`, the `/e` modifier and `create_function()` - all three had stopped executing by PHP 8.0, so on a current target they are dead code to delete rather than live sinks; on PHP 7 disable string assertions with `zend.assertions = -1` in `php.ini` - that directive arrived in 7.0, so a PHP 5 target uses `assert.active` instead
- Enable `display_errors = Off` in production so error messages don't reveal code-injection paths
- Test by submitting `system('id')` or `phpinfo()` as input values and confirming they are not executed
