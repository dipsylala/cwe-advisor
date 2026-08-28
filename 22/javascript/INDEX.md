# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - JavaScript

## LLM Guidance

Path Traversal in JavaScript/Node.js occurs when applications use unsanitized user input to construct file paths, allowing attackers to access files outside intended directories using sequences like `../`.

**Primary Defence:** Use indirect reference mapping (mapping user IDs to files) rather than accepting direct file paths. When direct paths are necessary, validate against an allowlist and resolve paths to ensure they remain within the intended directory.

## Key Principles

- Use indirect reference mapping with IDs/tokens instead of accepting file paths from users
- Validate all path inputs against strict allowlists of permitted files/directories
- Resolve and normalize paths, then compare real paths so symlinks cannot escape the base directory
- Reject inputs containing path traversal sequences (`../`, `..\\`, encoded variants)
- Apply principle of least privilege to file system permissions
- Treat a built module specifier as a path sink too - `require('./plugins/' + name)` and dynamic `import()` traverse out of the intended directory and execute what they load; resolve the name through a lookup map instead
- `path.normalize()` and `path.basename()` are not containment checks - `basename()` reduces input to a filename but says nothing about which directory the result lands in; resolve and compare against the base

## Taint Sinks

`fs.readFile()`, `fs.createReadStream()`, `res.sendFile()`, `res.download()`, `require()`/`import()` with a built path, `path.join()` with unvalidated input, archive entry paths from `adm-zip`/`unzipper`/`yauzl`/`tar` (Zip Slip)

## Remediation Steps

- Replace direct file path parameters with indirect references (database IDs, UUIDs)
- Validate the value the framework already decoded - Express populates `req.params`/`req.query` decoded, so a further `decodeURIComponent()` manufactures `../` and throws `URIError` on a malformed sequence such as `%c0%ae`
- Use `path.resolve()` for path construction and `fs.realpathSync.native()` before containment checks
- Verify the real requested path stays inside the real base directory using `path.relative()` - reject when the result starts with `..` or `path.isAbsolute()` is true
- Implement allowlist validation for permitted file extensions and names
- Sanitize input by rejecting `..`, null bytes, and encoded traversal attempts
- Configure Express static middleware with `dotfiles: 'deny'` and strict root directories
- Archive extraction (Zip Slip): treat entry paths from `adm-zip`, `unzipper`, `yauzl`, or `tar` as untrusted - resolve each with `path.resolve()` against the extraction directory and check containment before writing; `extract-zip` validates this internally in current versions, but manual extraction loops with lower-level libraries do not
