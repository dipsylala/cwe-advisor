# CWE-41: Improper Resolution of Path Equivalence - JavaScript

## LLM Guidance

In Node.js this appears when a path is validated in one representation and opened in another - most commonly a check for `..` run against a raw URL component before `decodeURIComponent()`, so `%2e%2e%2f` passes the check and becomes `../` before the read. `path.join()` and `path.resolve()` normalize `.` and `..` but neither enforces containment nor resolves symbolic links. The fix is to decode at most once, resolve to an absolute path, and verify containment with `path.relative()`.

## Key Principles

- **Check whether the framework already does this before hand-rolling it.** `res.sendFile()` and `res.download()` given the `root` option are documented to "validate that the relative path provided as `path` will resolve within the given `root` option" - so a finding on either is usually "the `root` option is missing", not "write a containment check". Without `root`, `res.download` resolves the caller's string with `path.resolve()` and applies no containment at all
- Know the limit of that built-in check: it is lexical - a decode, a `..`-segment regex, then a join under the root. It never calls `fs.realpath`, so a symlink inside the root still escapes
- Decode exactly once and validate the decoded form. Express documents that it decodes `req.params` with `decodeURIComponent`; `req.query` is decoded too, by the query parser rather than by Express itself, and Express does not document it. Express 5 changed that parser's default from `extended` to `simple` and made wildcard params arrays rather than strings
- Verify containment with `path.relative(base, resolved)` and reject a result that is `..`, starts with `..` plus `path.sep`, is absolute, or is the empty string - `resolved.startsWith(base)` accepts a sibling such as `/app/data-secret`, which is exactly CVE-2014-6394 in `send` (fixed in send 0.8.4, Express 4.8.8). An empty result means the target *is* the base directory
- `path.normalize()` and `path.basename()` are not containment checks; resolve against the base and compare. Node's own `path.normalize` was the vulnerable component in the September 2017 Node 8.5.0 path-validation advisory, so treat it as a formatter rather than a control
- Resolve symlinks with `fs.realpath()` on both the base and the target, then repeat the `path.relative()` check - `path.resolve()` is purely lexical and cannot see a link. `fs.realpath` raises `ENOENT` for a path that does not exist, so order it after the existence decision, and note `fsPromises.realpath` follows `realpath.native` semantics rather than `fs.realpath`'s
- Confirm the target with `fs.stat().isFile()` before reading, so directories and special files are refused; `fs.stat` follows links, `fs.lstat` does not
- Read from the realpath-resolved variable, not from the originally constructed path, so the value checked is the value opened
- Where only a filename is expected, reject input containing a path separator rather than reducing it with `path.basename()` - and reject `\` explicitly, since on POSIX it is an ordinary character and `path.sep` is only `/`

## Taint Sinks

`fs.readFile()`, `fs.createReadStream()`, `fs.stat()`, `res.sendFile()`/`res.download()` without `root`, `path.join()` with unvalidated input

## Remediation Steps

- Locate - find path checks (`includes('..')`, `startsWith(base)`) applied to a value from `req.query`, `req.params`, or a hand-parsed URL component
- Trace data flow - determine which representation the check sees and which the file call sees, and how many times the value is decoded between them
- Replace the unsafe pattern - pass `root` to `res.sendFile`/`res.download` where those are the sink; otherwise resolve the base once with `path.resolve()` at module scope, resolve the request value against it, and check with `path.relative()`
- Bind, encode, validate, or authorize - reject separators where a bare filename is expected, and apply an extension allowlist where only certain types are legitimate
- Break taint after allowlist validation - pass the `fs.realpath()` result to the read, never the raw request value
- Harden configuration - serve static content through `express.static()` with a fixed root rather than hand-rolled file serving where possible, and set `dotfiles` explicitly: the default is `'ignore'` in serve-static 2.x, while Express 4's default leaves files *inside* a dot-directory served
- Test - assert equivalent spellings (`dir`, `dir/`, `dir/.`, `dir//`) reach the same decision, that `%2e%2e%2f` and `../` are both refused, that a symlink out of the base is refused, and that a legitimate file still downloads
