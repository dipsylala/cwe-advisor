# CWE-597: Use of Wrong Operator in String Comparison - PHP

## LLM Guidance

PHP's loose equality operator (`==`) performs type juggling before comparison, creating security bypass conditions that do not exist in strictly typed languages. Examples: `"0" == false` is `true`; `"admin" == 0` is `true` in PHP 7 (any non-numeric string equals 0); `"1e0" == "1"` is `true`. Authentication and authorization checks using `==` for string comparison can be bypassed by an attacker supplying a type-juggled value. Always use strict equality (`===`) for security-sensitive comparisons.

## Key Principles

- Use `===` for all security-sensitive comparisons — it checks both value and type without coercion
- Hash comparison for passwords must use `password_verify()`, never `==` or `===` directly on hashes
- Use `hash_equals()` for comparing MAC tags, tokens, and other secrets to prevent timing attacks
- Never compare user-supplied values with `==` against numeric-looking strings, booleans, or `null`
- Enable strict types (`declare(strict_types=1)`) at the file level to surface type mismatches early

## Remediation Steps

- Search for `==` comparisons involving strings in authentication, token validation, and authorization logic
- Replace `$userInput == $expected` with `$userInput === $expected` for string comparisons
- Replace direct hash comparisons with `password_verify($plaintext, $hash)` for password checks
- Replace token comparisons with `hash_equals($knownGoodToken, $userToken)` to prevent timing attacks
- Review comparisons involving values that could arrive as integers (`0`, `1`) alongside string role names
- Enable `declare(strict_types=1)` and fix any resulting type errors to harden the codebase

## Safe Pattern

```php
<?php
declare(strict_types=1);

// SAFE: strict equality for role/permission check
function checkRole(string $userRole, string $requiredRole): bool {
    return $userRole === $requiredRole;  // No type juggling
}

// SAFE: password verification using password_verify
function authenticate(string $plainPassword, string $storedHash): bool {
    return password_verify($plainPassword, $storedHash);
}

// SAFE: constant-time token comparison
function validateToken(string $submittedToken, string $expectedToken): bool {
    return hash_equals($expectedToken, $submittedToken);
}

// UNSAFE examples (do not use):
// $role == "admin"         — type juggling risk
// $token == $expectedToken — timing attack risk, and type juggling risk
// md5($password) == $hash  — both weak hash and comparison risk
```
