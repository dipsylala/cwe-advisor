# CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')

## LLM Guidance

Remote File Inclusion (RFI) in PHP occurs when untrusted input is used in file inclusion functions (`include`, `require`, `include_once`, `require_once`) without proper validation, allowing attackers to execute arbitrary code from remote sources. The core fix is to never allow untrusted input to select files for inclusion - use allowlists and disable remote file inclusion entirely. CWE-98 is the PHP-specific variant of CWE-829 (inclusion of functionality from an untrusted control sphere); use CWE-829 for dynamic imports and equivalents in other languages, and CWE-73 where the finding is about the path construction rather than the include mechanism.

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
