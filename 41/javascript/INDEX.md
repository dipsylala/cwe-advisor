# CWE-41: Improper Resolution of Path Equivalence - JavaScript

## LLM Guidance

In Node.js this appears when a path is validated in one representation and opened in another - most commonly a check for `..` run against a raw URL component before `decodeURIComponent()`, so `%2e%2e%2f` passes the check and becomes `../` before the read. `path.join()` and `path.resolve()` normalize `.` and `..` but neither enforces containment nor resolves symbolic links. The fix is to decode at most once, resolve to an absolute path, and verify containment with `path.relative()`.

## Key Principles

- Decode exactly once and validate the decoded form: Express already decodes `req.query` and `req.params`, so decoding those again creates the same mismatch in the opposite direction
- Verify containment with `path.relative(base, resolved)` and reject a result that is `..`, starts with `..` plus `path.sep`, or is absolute - `resolved.startsWith(base)` accepts a sibling such as `/app/data-secret`
- `path.normalize()` and `path.basename()` are not containment checks; resolve against the base and compare
- Resolve symlinks with `fs.realpath()` on both the base and the target, then repeat the `path.relative()` check - `path.resolve()` is purely lexical and cannot see a link
- Confirm the target with `fs.stat().isFile()` before reading, so directories and special files are refused
- Read from the realpath-resolved variable, not from the originally constructed path, so the value checked is the value opened
- Where only a filename is expected, reject input containing a path separator rather than reducing it with `path.basename()`

## Taint Sinks

`fs.readFile()`, `fs.createReadStream()`, `fs.stat()`, `res.sendFile()`, `res.download()`, `path.join()` with unvalidated input

## Remediation Steps

- Locate - find path checks (`includes('..')`, `startsWith(base)`) applied to a value from `req.query`, `req.params`, or a hand-parsed URL component
- Trace data flow - determine which representation the check sees and which the file call sees, and how many times the value is decoded between them
- Replace the unsafe pattern - resolve the base once with `path.resolve()` at module scope, resolve the request value against it, and check with `path.relative()`
- Bind, encode, validate, or authorize - reject separators where a bare filename is expected, and apply an extension allowlist where only certain types are legitimate
- Break taint after allowlist validation - pass the `fs.realpath()` result to the read, never the raw request value
- Harden configuration - serve static content through `express.static()` with `dotfiles: 'deny'` and a fixed root rather than hand-rolled file serving where possible
- Test - assert equivalent spellings (`dir`, `dir/`, `dir/.`, `dir//`) reach the same decision, that `%2e%2e%2f` and `../` are both refused, that a symlink out of the base is refused, and that a legitimate file still downloads
