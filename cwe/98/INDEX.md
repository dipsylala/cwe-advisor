# CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')

## LLM Guidance

The PHP-specific variant of CWE-829. Use CWE-829 for dynamic imports and their equivalents in other languages, and CWE-73 where the finding is about how the path is constructed rather than about the include mechanism itself.

## Key Principles

- Never use untrusted input directly in `include`/`require` functions
- Disable `allow_url_include` and `allow_url_fopen` in php.ini
- Map user input to predefined allowlists, not file paths
- Validate that resolved paths stay within expected directories, comparing canonicalized paths rather than trusting a fixed prefix or an appended `.php` suffix - a prefix is a string operation, not a boundary
- `include` accepts a stream URL wherever it accepts a path, so `php://filter/...`, `data://`, and `http://` are inclusion targets even with no traversal sequence; confirm the value is a plain relative filename before it reaches the include
- Prefer autoloading over dynamic file inclusion

## Remediation Steps

- Trace data flow - Identify where untrusted data (HTTP params, cookies, external APIs) reaches file inclusion functions
- Implement allowlists - Map user input to predefined file paths using arrays or switch statements
- Disable remote inclusion - Set `allow_url_include=0` and `allow_url_fopen=0` in php.ini
- Validate paths - Use `realpath()` to resolve paths and verify they're within allowed directories
- Remove dynamic inclusion - Replace variable-based includes with explicit imports or autoloading
- Reject, do not strip - if dynamic inclusion is unavoidable, refuse any value that is not a single plain filename matching a strict pattern, rather than removing separators from it
