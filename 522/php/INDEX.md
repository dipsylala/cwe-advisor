# CWE-522: Insufficiently Protected Credentials - PHP

## LLM Guidance

Insufficiently protected credentials in PHP commonly appear as database passwords or API keys hardcoded in `config.php`, committed `.env` files, or passwords stored with `md5()` / `sha1()`. Load credentials from environment variables (via `$_ENV` or `getenv()`) set outside the web root, and hash passwords with PHP's built-in `password_hash()` using `PASSWORD_BCRYPT` or `PASSWORD_ARGON2ID`. Never store credentials in files inside the web-accessible document root.

## Key Principles

- Store secrets in environment variables set by the server (Apache `SetEnv`, Nginx `fastcgi_param`, or a `.env` file outside the web root loaded by `vlucas/phpdotenv`)
- Hash passwords with `password_hash($password, PASSWORD_BCRYPT)` or `PASSWORD_ARGON2ID`; verify with `password_verify()`
- Never use `md5()`, `sha1()`, or any reversible function for password storage
- Add `.env` to `.htaccess` deny rules and to `.gitignore` to prevent exposure
- Rotate any credentials that appear in version control history and treat them as compromised

## Remediation Steps

- Remove hardcoded credentials from PHP source files and configuration arrays
- Move secrets to a `.env` file outside the web root and load with `vlucas/phpdotenv` or read with `getenv()`
- Replace `md5($password)` / `sha1($password)` password storage with `password_hash($password, PASSWORD_BCRYPT, ['cost' => 12])`
- Replace direct hash comparison with `password_verify($plaintext, $storedHash)`
- Add `.env` to `.gitignore` and add `Deny from all` in `.htaccess` for `.env` as defence-in-depth
- Scan git history for committed credentials using `git log -p | grep -i password`

## Safe Pattern

```php
<?php
// Load .env from outside web root (using vlucas/phpdotenv)
require_once __DIR__ . '/../vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

// Read credentials from environment — never hardcoded
$dsn = sprintf('mysql:host=%s;dbname=%s', getenv('DB_HOST'), getenv('DB_NAME'));
$pdo = new PDO($dsn, getenv('DB_USER'), getenv('DB_PASS'));

// Password hashing on registration
$hashedPassword = password_hash($plainPassword, PASSWORD_BCRYPT, ['cost' => 12]);
// Store $hashedPassword in the database

// Password verification on login
if (password_verify($submittedPassword, $storedHash)) {
    // Authentication successful
}

// Rehash if algorithm/cost has changed
if (password_needs_rehash($storedHash, PASSWORD_BCRYPT, ['cost' => 12])) {
    $newHash = password_hash($plainPassword, PASSWORD_BCRYPT, ['cost' => 12]);
    // Update stored hash
}
```
