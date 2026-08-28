# CWE-41: Improper Resolution of Path Equivalence - PHP

## LLM Guidance

In PHP this appears when a user-supplied path is filtered with `strpos()`, `str_contains()` or `str_replace()` instead of being canonicalized. A single-pass `str_replace('../', '')` is defeated by `....//`, which reassembles into `../` once the inner match is removed, and a `..` denylist never sees the payloads that need no `..` at all - an absolute path, or a symbolic link inside the served directory. The fix is `realpath()` followed by a separator-terminated containment check against the canonicalized base directory.

## Key Principles

- Canonicalize with `realpath()`, which resolves `.`, `..` and symbolic links; string filtering validates a value the filesystem never sees
- `realpath()` returns `false` unless every component already exists - handle that as "not found" before comparing, and never fall back to the unresolved string with `realpath($p) ?: $p`
- Compare with a boundary: `strpos($real, rtrim($base, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0`, so the sibling `/var/www/uploads_evil` does not pass a check meant for `/var/www/uploads`
- Canonicalize the base directory too, once, and compare canonical against canonical
- Where only a filename is expected, reject input where `basename($file) !== $file` or which contains `/`, `\`, or a null byte - reject rather than reduce, so the attempt is visible in logs
- Confirm the target with `is_file()` before reading, so directories and special files are refused
- Reject equivalent spellings rather than trying to enumerate them: `//`, `/./`, and a trailing `/.` all reach the same file through strings no filter written for the plain form will match

## Taint Sinks

`readfile()`, `file_get_contents()`, `fopen()`, `unlink()`, `copy()`, `is_file()`, `scandir()`

## Remediation Steps

- Locate - find path checks built from `strpos()`, `str_contains()`, `str_replace()`, or `preg_replace()` applied to `$_GET`, `$_POST`, `$_REQUEST`, or an uploaded filename
- Trace data flow - follow the value from the superglobal through every concatenation to the check and then to the filesystem call, confirming both operate on the same variable
- Replace the unsafe pattern - canonicalize the base with `realpath()` once, build the candidate, canonicalize it, handle `false`, then apply the separator-terminated containment check
- Bind, encode, validate, or authorize - reject separators and null bytes where a bare filename is expected, and apply an extension allowlist where only certain types are legitimate
- Break taint after allowlist validation - pass the `realpath()` result to the sink, never the request value
- Harden configuration - set `open_basedir` as a process-wide backstop and restrict filesystem permissions on the served directory; neither is the remediation on its own
- Test - assert equivalent spellings (`dir`, `dir/`, `dir/.`, `dir//`) reach the same decision, that `....//` and a symlink out of the base are both refused, and that a legitimate file still downloads
