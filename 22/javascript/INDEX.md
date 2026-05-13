# CWE-22: Path Traversal - JavaScript/Node.js

## LLM Guidance

Path Traversal in JavaScript/Node.js occurs when applications use unsanitized user input to construct file paths, allowing attackers to access files outside intended directories using sequences like `../`.

**Primary Defence:** Use indirect reference mapping (mapping user IDs to files) rather than accepting direct file paths. When direct paths are necessary, validate against an allowlist and resolve paths to ensure they remain within the intended directory.

## Key Principles

- Use indirect reference mapping with IDs/tokens instead of accepting file paths from users
- Validate all path inputs against strict allowlists of permitted files/directories
- Resolve and normalize paths, then compare real paths so symlinks cannot escape the base directory
- Reject inputs containing path traversal sequences (`../`, `..\\`, encoded variants)
- Apply principle of least privilege to file system permissions

## Remediation Steps

- Replace direct file path parameters with indirect references (database IDs, UUIDs)
- Decode input with `decodeURIComponent()` and normalise Unicode with `.normalize('NFC')` before any path construction
- Use `path.resolve()` for path construction and `fs.realpathSync.native()` before containment checks
- Verify the real requested path stays inside the real base directory using `path.relative()`
- Implement allowlist validation for permitted file extensions and names
- Sanitize input by rejecting `..`, null bytes, and encoded traversal attempts
- Configure Express static middleware with `dotfiles: 'deny'` and strict root directories

## Safe Pattern

```javascript
const path = require('path');
const fs = require('fs');

const BASE_DIR = path.resolve('./uploads');
const REAL_BASE_DIR = fs.realpathSync.native(BASE_DIR);

function safeReadFile(userFilename) {
  // Decode URL encoding and normalise Unicode before any path logic
  const decoded = decodeURIComponent(userFilename).normalize('NFC');

  const requestedPath = path.resolve(BASE_DIR, decoded);
  const realRequestedPath = fs.realpathSync.native(requestedPath);
  const relative = path.relative(REAL_BASE_DIR, realRequestedPath);

  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('Access denied');
  }

  return fs.readFileSync(realRequestedPath);
}
```
