# CWE-502: Deserialization of Untrusted Data - PHP

## LLM Guidance

PHP's `unserialize()` can instantiate arbitrary classes and invoke magic methods (`__wakeup()`, `__destruct()`, `__toString()`), enabling remote code execution via gadget chains or property-oriented programming. Primary fix: Replace `unserialize()` with `json_decode()` for untrusted data. If `unserialize()` is unavoidable, use the `allowed_classes` option (PHP 7.0+) as a last-resort mitigation.

## Key Principles

- Replace deserialization with safer data formats (JSON, simple arrays)
- Never deserialize user-controlled or untrusted input
- Implement integrity checks (HMAC signatures) before deserialization
- Restrict class instantiation using `allowed_classes` whitelist
- Phar deserialization is a distinct vector from direct `unserialize()` calls - on PHP versions before 8.0, any filesystem function (`file_exists()`, `fopen()`, `getimagesize()`, `is_dir()`, etc.) that accepts a user-controlled path could trigger object deserialization via the `phar://` stream wrapper against an attacker-uploaded archive; PHP 8.0+ only deserializes phar metadata on explicit `Phar` access (`new Phar()`, `Phar::getMetadata()`), not through general stream-wrapper file operations. Validate paths and reject uploads with a `.phar` signature regardless of version
- Apply defence-in-depth: input validation, least privilege, code audits

## Remediation Steps

- Search codebase for all `unserialize()` calls on external data
- Replace with `json_decode()` where possible, refactoring data structures as needed
- For required `unserialize()` use cases, add HMAC signature validation
- Apply `allowed_classes => []` or whitelist specific safe classes
- Review magic methods (`__wakeup`, `__destruct`, `__toString`) for exploitable logic
- Test thoroughly to ensure data integrity and functionality

## Safe Pattern

```php
// SAFE: Use JSON for untrusted data
$data = json_decode($_POST['data'], true);

// If unserialize() is required, validate with HMAC
$signature = hash_hmac('sha256', $serialized, SECRET_KEY);
if (!hash_equals($signature, $_POST['signature'])) {
    throw new Exception('Invalid signature');
}

// Restrict to safe classes only
$data = unserialize($serialized, ['allowed_classes' => ['SafeClass']]);
```
