# CWE-41: Improper Resolution of Path Equivalence - PHP

## LLM Guidance

In PHP this appears when a user-supplied path is filtered with `strpos()`, `str_contains()` or `str_replace()` instead of being canonicalized. A single-pass `str_replace('../', '')` is defeated by `....//`, which reassembles into `../` once the inner match is removed, and a `..` denylist never sees the payloads that need no `..` at all - an absolute path, or a symbolic link inside the served directory. The fix is `realpath()` followed by a separator-terminated containment check against the canonicalized base directory.

## Key Principles

- Canonicalize with `realpath()`, which "expands all symbolic links and resolves references to `/./`, `/../` and extra `/` characters"; string filtering validates a value the filesystem never sees
- Two documented limits on that, both directly about path equivalence: on Windows, "junctions and symbolic links to directories are only expanded by one level", and "for case-insensitive filesystems `realpath()` may or may not normalize the character case". Neither is a reason to skip it, but neither lets `realpath()` alone settle a link or a case-spelling question
- `realpath()` returns `false` for more reasons than a missing file - the manual names lacking execute permission on any directory in the hierarchy, and the implementation also returns `false` for a path outside `open_basedir`. Handle `false` as "reject" rather than "not found", and never fall back to the unresolved string with `realpath($p) ?: $p`
- Compare with a boundary: `strpos($real, rtrim($base, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0`, so the sibling `/var/www/uploads_evil` does not pass a check meant for `/var/www/uploads`. Use `===` because `strpos()` returns `0` for a match at the start and `false` for no match
- Canonicalize the base directory too, once, and compare canonical against canonical - `realpath()` strips trailing delimiters from its result, so both sides come back in one spelling
- Where only a filename is expected, reject input where `basename($file) !== $file` or which contains `/`, `\`, or a null byte - reject rather than reduce, so the attempt is visible in logs. Note `basename()` is locale-aware and the manual declares its behaviour **undefined** when the path contains bytes invalid for the current locale, so it is a filter, not an authority. On non-Windows `\` is not a separator, which is why it needs rejecting separately
- A null byte in a path argument is already fatal - `ValueError` since PHP 8.0, a warning or `TypeError` before - so validate it for a clear error rather than to prevent the truncation the manual's older guidance describes
- Confirm the target with `is_file()` before reading, so directories and special files are refused. Its result is served from the stat cache, so where the file may change between the check and the open, call `clearstatcache()` - and treat the remaining window as unclosed
- Reject equivalent spellings rather than trying to enumerate them: `//`, `/./`, and a trailing `/.` all reach the same file through strings no filter written for the plain form will match

## Taint Sinks

`readfile()`, `file_get_contents()`, `fopen()`, `include`/`require`, `unlink()`, `copy()`, `is_file()`, `scandir()`

## Remediation Steps

- Locate - find path checks built from `strpos()`, `str_contains()`, `str_replace()`, or `preg_replace()` applied to `$_GET`, `$_POST`, `$_REQUEST`, or an uploaded filename
- Trace data flow - follow the value from the superglobal through every concatenation to the check and then to the filesystem call, confirming both operate on the same variable
- Replace the unsafe pattern - canonicalize the base with `realpath()` once, build the candidate, canonicalize it, handle `false`, then apply the separator-terminated containment check
- Bind, encode, validate, or authorize - reject separators and null bytes where a bare filename is expected, and apply an extension allowlist where only certain types are legitimate
- Break taint after allowlist validation - pass the `realpath()` result to the sink, never the request value
- Harden configuration - set `open_basedir` as a backstop and restrict filesystem permissions on the served directory. The manual's own caution is that it "is just an extra safety net, that is in no way comprehensive, and can therefore not be relied upon when security is needed"; note also that enabling it disables the realpath cache
- Test - assert equivalent spellings (`dir`, `dir/`, `dir/.`, `dir//`) reach the same decision, that `....//` and a symlink out of the base are both refused, and that a legitimate file still downloads
