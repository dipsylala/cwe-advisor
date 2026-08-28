# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - PHP

## LLM Guidance

Path Traversal in PHP appears where a request value is concatenated into a path passed to `file_get_contents()`, `readfile()`, `fopen()`, `unlink()` or `copy()` - PHP has no path-joining function that enforces a base directory, so `$base . '/' . $_GET['file']` does exactly what it says. The canonicalizing function is `realpath()`, which resolves `.`, `..` and symbolic links but returns `false` unless every component of the path already exists - and also on a directory the process cannot traverse, on a path inside a Phar, and on an `open_basedir` violation, so a `false` means "could not resolve", not "does not exist". Test it with `=== false`, since it coerces to the empty string in a comparison. On Windows it expands a junction or directory symlink by only one level. That makes it correct for validating a read and wrong for validating a write destination, which is the single most common source of broken fixes for this CWE in PHP.

## Key Principles

- Prefer indirect reference mapping: the request supplies a key, an `array_key_exists()` lookup on a fixed map supplies the path, and no string exists for `..` to appear in
- For reads, build the path, canonicalize it with `realpath()`, handle the `false` return as "not found" before comparing anything, then confirm containment
- Compare with the separator: `$full === $base || str_starts_with($full, $base . DIRECTORY_SEPARATOR)` - a bare `str_starts_with($full, $base)` accepts the sibling directory `/var/www/documents_backup`
- Never write `realpath($path) ?: $path` - the fallback silently downgrades the canonical check to a textual one for exactly the traversal inputs it was meant to catch
- For writes, the destination does not exist yet, so resolve the *parent* with `realpath()` and reject a filename that is empty, `.`, `..`, or contains `/` or `\` - a null-byte check is no longer the control it once was, since path truncation was fixed in PHP 5.3.4 and a NUL in a path argument raises a `ValueError` from PHP 8.0; open with mode `'x'`/`'xb'` so an existing file or planted symlink is refused rather than truncated
- `basename()` is a reducer, not a containment control - it is separator- and locale-dependent (on Linux `basename('..\..\etc\passwd')` returns the whole string) and says nothing about which directory the result lands in
- A path string is also a URL to PHP's stream layer: `php://filter/convert.base64-encode/resource=config` discloses source without any traversal sequence, and `realpath()` returns `false` for a wrapper, so confirm the input is a plain relative filename before canonicalizing
- Set `open_basedir` as a process-wide backstop, never as the remediation - it cannot separate one user's files from another's inside the permitted trees

## Taint Sinks

`file_get_contents()`, `readfile()`, `fopen()`, `file_put_contents()`, `unlink()`, `copy()`, `rename()`, `scandir()`, `ZipArchive::getNameIndex()` (Zip Slip)

## Remediation Steps

- Locate - find where `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, or an uploaded filename is concatenated into a path reaching a filesystem function
- Trace data flow - follow the value through every concatenation and helper; the check and the open must operate on the same variable, not on two separately built strings
- Replace the unsafe pattern - map an identifier to a path through a fixed array where possible; otherwise canonicalize with `realpath()` and apply the separator-terminated containment check before reading
- Bind, encode, validate, or authorize - reject a filename containing a separator wherever a single component is what the code expects, and add an extension allowlist where only certain file types are legitimate
- Break taint after allowlist validation - pass the map's value (or the `realpath()` result) to the sink, never the original request value
- Harden configuration - add `open_basedir` for the application's directories and apply the containment check to every entry in a hand-rolled archive extraction loop, and do not assume `ZipArchive::extractTo()` covers it - the manual documents no entry-name or traversal sanitisation for it
- Test - assert a legitimate subdirectory read still succeeds, that `../../../etc/passwd` and a sibling such as `../documents_backup/notes.txt` are refused, and that a missing file is reported as "not found" rather than passing the containment check - outside `declare(strict_types=1)` a `false` from `realpath()` coerces to the empty string, and `str_starts_with($base, '')` is true, so an unchecked failure fails open rather than raising
