# CWE-597: Use of Wrong Operator in String Comparison - PHP

## LLM Guidance

PHP's loose equality operator (`==`) performs type juggling before comparison, creating security bypass conditions that do not exist in strictly typed languages. Examples: `"0" == false` is `true`; `"admin" == 0` is `true` in PHP 7 (any non-numeric string equals 0); `"1e0" == "1"` is `true`. Authentication and authorization checks using `==` for string comparison can be bypassed by an attacker supplying a type-juggled value. Always use strict equality (`===`) for security-sensitive comparisons.

## Key Principles

- Use `===` for all security-sensitive comparisons - it checks both value and type without coercion
- Hash comparison for passwords must use `password_verify()`, never `==` or `===` directly on hashes
- Use `hash_equals()` for comparing MAC tags, tokens, and other secrets to prevent timing attacks
- Never compare user-supplied values with `==` against numeric-looking strings, booleans, or `null`
- `declare(strict_types=1)` does not fix this CWE: it only governs type coercion for typed function/method parameters and return values, and has no documented effect on the `==`/`===` operators - use static analysis (PHPStan or Psalm with a strict-comparison ruleset) to catch new loose comparisons instead
- `in_array()` and `array_search()` compare loosely unless the third argument is `true`, so an allowlist check with either is subject to the same coercion as `==`
- The classic demonstration is two strings whose MD5 digests both begin `0e` (`md5('240610708')` and `md5('QNKCDZO')`), which `==` treats as equal because both parse as `0` in scientific notation - `===` and `hash_equals()` do not
- Use `hash_equals()` for any secret comparison, which is both strict and constant-time

## Taint Sinks

`==` loose comparison on strings, direct `==`/`===` comparison of password hashes, `==` on tokens instead of `hash_equals()`

## Remediation Steps

- Search for `==` comparisons involving strings in authentication, token validation, and authorization logic
- Replace `$userInput == $expected` with `$userInput === $expected` for string comparisons
- Replace direct hash comparisons with `password_verify($plaintext, $hash)` for password checks
- Replace token comparisons with `hash_equals($knownGoodToken, $userToken)` to prevent timing attacks
- Review comparisons involving values that could arrive as integers (`0`, `1`) alongside string role names
- Test the fixed comparison against type-juggling edge cases (`"0"`, empty string, boolean `false`, numeric-looking strings) to confirm the vulnerability is closed, not just the originally reported input
