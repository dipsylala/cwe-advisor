# CWE-502: Deserialization of Untrusted Data - PHP

## LLM Guidance

PHP's `unserialize()` can instantiate arbitrary classes and invoke magic methods (`__wakeup()`, `__destruct()`, `__toString()`), enabling remote code execution via gadget chains or property-oriented programming. Which fix is primary depends on what already exists in the serialized form. Where the payload is data only (arrays, scalars - a cart, a preference map) and serialized values already sit in cookies, sessions or database rows, keep `unserialize()` and pass `['allowed_classes' => false]` (PHP 7.0+): every object in the payload becomes `__PHP_Incomplete_Class`, no magic method runs, and existing data still decodes. Replace `unserialize()` with `json_decode()` only where every producer switches to `json_encode()` in the same change - `json_decode()` of an existing serialized string returns `null`, so a decoder-only swap silently empties every stored value while looking like a clean fix.

## Key Principles

- Replace deserialization with safer data formats (JSON, simple arrays) where every writer of the value moves with the reader
- Never `unserialize()` user-controlled or untrusted input with object construction enabled
- Implement integrity checks (HMAC signatures) before deserialization
- `allowed_classes => false` when the payload should carry no objects at all; an explicit array of class names only when a named class must round-trip. Unknown classes decode to `__PHP_Incomplete_Class` rather than failing, so a code path that later calls a method on the value needs a type check, not just the option
- Phar deserialization is a distinct vector from direct `unserialize()` calls - on PHP versions before 8.0, any filesystem function (`file_exists()`, `fopen()`, `getimagesize()`, `is_dir()`, etc.) that accepts a user-controlled path could trigger object deserialization via the `phar://` stream wrapper against an attacker-uploaded archive; PHP 8.0+ only deserializes phar metadata on explicit `Phar` access (`new Phar()`, `Phar::getMetadata()`), not through general stream-wrapper file operations. Validate paths and reject uploads with a `.phar` signature regardless of version
- Apply defence-in-depth: input validation, least privilege, code audits

## Taint Sinks

`unserialize()`, `phar://` stream wrapper access (`file_exists()`, `fopen()`, `getimagesize()`, `is_dir()`) on pre-8.0 PHP

## Remediation Steps

- Search codebase for all `unserialize()` calls on external data
- Establish who writes the value before changing who reads it: a cookie, session field or column written by `serialize()` elsewhere in the codebase (or by an older release still in the wild) is the contract the fix has to keep
- Where existing serialized data must still be read, add `['allowed_classes' => false]` (or an explicit class list) to the `unserialize()` call - this keeps the wire format and closes the magic-method vector
- Replace with `json_decode()` only where every producer of the value moves to `json_encode()` in the same change; if a producer cannot change, the decoder cannot either
- Where `unserialize()` must accept objects, add HMAC signature validation - compare the `hash_hmac('sha256', ...)` digest with `hash_equals()`, not `==`
- Review magic methods (`__wakeup`, `__destruct`, `__toString`) for exploitable logic
- Test thoroughly to ensure data integrity and functionality
