# CWE-502: Deserialization of Untrusted Data - PHP

## LLM Guidance

PHP's `unserialize()` can instantiate arbitrary classes and invoke magic methods (`__wakeup()`, `__destruct()`, `__toString()`), enabling remote code execution via gadget chains or property-oriented programming. Which fix is primary depends on what already exists in the serialized form. Where the payload is data only (arrays, scalars - a cart, a preference map) and serialized values already sit in cookies, sessions or database rows, keep `unserialize()` and pass `['allowed_classes' => false]` (PHP 7.0+): every object in the payload becomes `__PHP_Incomplete_Class`, no magic method runs, and existing data still decodes. Replace `unserialize()` with `json_decode()` only where every producer switches to `json_encode()` in the same change - `json_decode()` of an existing serialized string returns `null`, so a decoder-only swap silently empties every stored value while looking like a clean fix.

## Key Principles

- Replace deserialization with safer data formats (JSON, simple arrays) where every writer of the value moves with the reader
- Never `unserialize()` user-controlled or untrusted input with object construction enabled
- Implement integrity checks (HMAC signatures) before deserialization
- Read what the code does with the result before choosing the option. An `instanceof`, a method call or a typed property access on the decoded value means the payload legitimately carries that class - pass it by name, `['allowed_classes' => [ShoppingCart::class]]` - because `false` turns it into `__PHP_Incomplete_Class`, the `instanceof` fails, and every legitimate value silently becomes the empty-case fallback. `false` is for a payload of arrays and scalars only
- Phar deserialization is a distinct vector from direct `unserialize()` calls - on PHP versions before 8.0, any filesystem function (`file_exists()`, `fopen()`, `getimagesize()`, `is_dir()`, etc.) that accepts a user-controlled path could trigger object deserialization via the `phar://` stream wrapper against an attacker-uploaded archive; PHP 8.0+ only deserializes phar metadata on explicit `Phar` access (`new Phar()`, `Phar::getMetadata()`), not through general stream-wrapper file operations. Validate paths and reject uploads with a `.phar` signature regardless of version
- Apply defence-in-depth: input validation, least privilege, code audits

## Taint Sinks

`unserialize()`, `phar://` stream wrapper access (`file_exists()`, `fopen()`, `getimagesize()`, `is_dir()`) on pre-8.0 PHP

## Remediation Steps

- Search codebase for all `unserialize()` calls on external data
- Establish who writes the value before changing who reads it: a cookie, session field or column written by `serialize()` elsewhere in the codebase (or by an older release still in the wild) is the contract the fix has to keep
- Where existing serialized data must still be read, add `['allowed_classes' => false]` (or an explicit class list) to the `unserialize()` call - this keeps the wire format and closes the magic-method vector
- Replace with `json_decode()` only where every producer of the value moves to `json_encode()` in the same change; if a producer cannot change, the decoder cannot either. During a migration both formats exist at once, so read by detected format: a JSON value starts with `{` or `[`, a PHP-serialized one with a type prefix such as `a:`, `O:`, `s:`, `i:`, `b:` or `N;` - decode legacy rows with `unserialize($v, ['allowed_classes' => false])` and new rows with `json_decode()`, and rewrite legacy rows as JSON on read or in a batch so the `unserialize()` path retires
- Where `unserialize()` must accept objects, add HMAC signature validation - compare the `hash_hmac('sha256', ...)` digest with `hash_equals()`, not `==`
- Review magic methods (`__wakeup`, `__destruct`, `__toString`) for exploitable logic
- Test thoroughly to ensure data integrity and functionality
