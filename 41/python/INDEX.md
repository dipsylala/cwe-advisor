# CWE-41: Improper Resolution of Path Equivalence - Python

## LLM Guidance

In Python this appears when equivalent spellings of the same path (`/app/files`, `/app//files`, `/app/files/.`) bypass a string comparison that was never preceded by canonicalization - typically a `str.replace('../', '')` or an `os.path` string check in legacy code. The single-pass replace is defeated by `....//`, which reassembles into `../` after the inner match is removed. The fix is `Path.resolve(strict=True)` followed by `is_relative_to()`, with Unicode normalization applied before the path is built.

## Key Principles

- Canonicalize with `Path.resolve()`, which resolves `.`, `..` and symbolic links; `os.path.normpath()` and `os.path.abspath()` make no filesystem call and cannot see a link
- Verify containment with `is_relative_to()` (3.9+) or `relative_to()` in a `try`/`except ValueError` - both compare path components, unlike `str(path).startswith(str(base))`, which accepts the sibling `/app/files-secret`
- Resolve the allowed base once at module scope with `.resolve()` and compare canonical against canonical
- Reject rather than strip: a `replace()` sanitizer is bypassable and hides the attempt from logs, while an explicit rejection is visible and testable
- Apply `unicodedata.normalize('NFC', name)` before building the path - the same filename can arrive in NFC or NFD form, so a byte comparison against an allowlist can fail while the filesystem resolves both to the same file
- Reject null bytes and, where only a filename is expected, input containing `/` or `\` - `Path(name).name` on Linux leaves a backslash payload intact as a single strange filename
- `resolve(strict=True)` raises `FileNotFoundError` for a missing target, which suits a read; for a write destination resolve the *parent* instead, since the destination does not exist yet
- Confirm the target with `is_file()` before serving, so directories and special files are refused

## Taint Sinks

`open()`, `send_file()`, `os.remove()`, `shutil.copy()`, `os.path.join()` with unvalidated input, `os.listdir()`

## Remediation Steps

- Locate - find path comparisons or sanitizers (`replace('../', '')`, `'..' in path`, `startswith`) applied to `request.args`, `request.form`, or a path parameter
- Trace data flow - follow the value through every join to the check and then to the file operation, confirming the checked value and the opened value are the same variable
- Replace the unsafe pattern - normalize Unicode, build the candidate against the resolved base, call `resolve(strict=True)`, then verify `is_relative_to(ALLOWED_DIR)`
- Bind, encode, validate, or authorize - reject null bytes and separators where a bare filename is expected, and apply an extension allowlist where only certain types are legitimate
- Break taint after allowlist validation - pass the resolved path to the sink, never the raw request value
- Harden configuration - prefer `flask.send_from_directory()` or Django's `FileSystemStorage`, which apply containment themselves, over a hand-rolled check
- Test - assert equivalent spellings (`dir`, `dir/`, `dir/.`, `dir//`) reach the same decision, that `....//` and a symlink out of the base are both refused, that NFC and NFD spellings of the same name behave identically, and that a legitimate file still downloads
