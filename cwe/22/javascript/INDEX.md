# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - JavaScript

## LLM Guidance

Path Traversal in JavaScript/Node.js occurs when applications use unsanitized user input to construct file paths, allowing attackers to access files outside intended directories using sequences like `../`.

**Primary Defence:** Use indirect reference mapping (mapping user IDs to files) rather than accepting direct file paths. When direct paths are necessary, resolve them and check they remain within the intended directory; an allowlist of names or extensions is added only where the application defines which files are legitimate.

## Key Principles

- Use indirect reference mapping with IDs/tokens instead of accepting file paths from users
- Resolve and contain every path input; an allowlist of permitted files or directories is a separate decision, for where the application defines them, and the write-up says what it rejects
- Resolve and normalize paths, then compare real paths so symlinks cannot escape the base directory
- A `..` test on the raw input belongs only where no containment check exists; beside a resolved `path.relative()` check it is redundant and rejects a legitimate `notes..v2.txt`
- Apply principle of least privilege to file system permissions
- Treat a built module specifier as a path sink too - `require('./plugins/' + name)` and dynamic `import()` traverse out of the intended directory and execute what they load; resolve the name through a lookup map instead
- `path.normalize()` and `path.basename()` are not containment checks - `basename()` reduces input to a filename but says nothing about which directory the result lands in; resolve and compare against the base

## Taint Sinks

`fs.readFile()`, `fs.createReadStream()`, `res.sendFile()`/`res.download()` given a path built from input without the `root` option - with `root` set they are the containment mechanism, not the sink - `require()`/`import()` with a built path, `path.join()` with unvalidated input, archive entry paths from `adm-zip`/`unzipper`/`yauzl`/`tar` (Zip Slip)

## Remediation Steps

- Locate - find the sinks above and follow the path operand back to the request parameter, upload field, or archive entry it came from
- Replace direct file path parameters with indirect references (database IDs, UUIDs)
- Validate the value the framework already decoded - Express populates `req.params`/`req.query` decoded, so a further `decodeURIComponent()` manufactures `../` and throws `URIError` on a malformed sequence such as `%c0%ae`
- Use `fs.realpathSync.native()` (Node 9.2 and later) on both the candidate and the base before containment checks. Take care with `path.resolve()` for the construction itself: it processes segments right to left until it has an absolute path, so a user segment of `/etc/passwd` discards the base entirely - `path.join()` does not, which makes join the safer constructor and resolve the one needing a prior absolute-path rejection; `realpathSync` throws `ENOENT` for a destination that does not exist yet, so for an upload resolve the parent directory instead, check that, and require the supplied name to satisfy `path.basename(name) === name` and to be none of `''`, `'.'` or `'..'`, each of which passes that test unchanged
- Verify the real requested path stays inside the real base directory using `path.relative()` - reject when the result is exactly `..`, starts with `'..' + path.sep`, or satisfies `path.isAbsolute()` - noting Node's documentation says of that function "it's not safe for mitigating path traversals", so it earns its place here only as a check on `path.relative`'s output after both sides have been resolved, never as a test on raw input; testing for a bare leading `..` also rejects a legitimate file named `..foo`
- Where the application defines the permitted extensions or names, enforce that list and say so; do not add one for the fix alone
- Reject null bytes before resolving; do not add a `..` substring test on top of the `path.relative()` check above
- Pass the `root` option to `res.sendFile()` and `res.download()`. Express documents that with `root`
  set the path may be relative and even contain `..`, and Express validates that it resolves inside
  `root` - that is the framework's own containment mechanism and is preferable to a hand-written
  check. Without `root` the path must be absolute and nothing validates it
- Configure Express static middleware with `dotfiles: 'deny'` and strict root directories, noting the
  default is `'ignore'` (already not served) so this changes the response rather than closing a
  traversal, and that the check is on the path string without consulting disk
- Archive extraction (Zip Slip): treat entry paths from `adm-zip`, `unzipper`, `yauzl`, or `tar` as untrusted - resolve each with `path.resolve()` against the extraction directory and check containment before writing; a call to `extract-zip` is itself a finding rather than the fix: its last release was 2.0.1 in 2023 and CVE-2026-19693 and CVE-2026-56876 both escape the extraction directory through symlink entries, with no fixed release for either, so there is no version to pin. Reject symlink entries in the loop, or `lstat` the destination before writing and open with `wx`
- Test - assert a legitimate nested read (`sub/ok.txt`) still succeeds and that `../../etc/passwd`, an absolute `/etc/passwd` and a sibling-directory path are refused. The sibling case is the one `path.relative` gets right and a `startsWith(base)` prefix test gets wrong, so it is the assertion that tells the two apart
