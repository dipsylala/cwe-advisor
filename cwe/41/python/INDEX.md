# CWE-41: Improper Resolution of Path Equivalence - Python

## LLM Guidance

In Python this appears when equivalent spellings of the same path (`/app/files`, `/app//files`, `/app/files/.`) bypass a string comparison that was never preceded by canonicalization - typically a `str.replace('../', '')` or an `os.path` string check in legacy code. The single-pass replace is defeated by `....//`, which reassembles into `../` after the inner match is removed. The fix is `Path.resolve(strict=True)` followed by `is_relative_to()`.

## Key Principles

- Canonicalize with `Path.resolve()`, which resolves `..` and symbolic links; `os.path.normpath()` is documented as string manipulation that "may change the meaning of a path that contains symbolic links", and `os.path.abspath()` only prefixes the working directory. On Windows, symlink and junction resolution arrived in 3.8
- Build the candidate with care: joining an *absolute* segment discards the base entirely, so `Path(base) / userInput` returns `/etc/passwd` outright when the input is absolute, and the containment check then runs on a path the base never constrained. Reject an absolute input, or check `is_relative_to` after resolving rather than trusting the join
- Verify containment with `is_relative_to()` (3.9+) or `relative_to()` in a `try`/`except ValueError` - both compare path components, unlike `str(path).startswith(str(base))`, which accepts the sibling `/app/files-secret`. Note `is_relative_to` is itself string-based and "neither accesses the filesystem nor treats `..` segments specially", so it must run *after* `resolve()`, never instead of it
- Resolve the allowed base once at module scope with `.resolve()` and compare canonical against canonical
- Reject rather than strip: a `replace()` sanitizer is bypassable and hides the attempt from logs, while an explicit rejection is visible and testable
- Reject null bytes and, where only a filename is expected, input containing `/` or `\` - `Path(name).name` on Linux leaves a backslash payload intact as a single strange filename, because `\` is an ordinary character in the POSIX flavour
- **Unicode normalization is platform-specific, so do not normalize blindly.** On macOS the filesystem is normalization-insensitive - HFS+ stores a decomposed form, APFS preserves what you supply and matches variants by hashing the decomposed form - so NFC and NFD spellings find the same file. On default ext4 they do not: names are opaque byte strings, so the two spellings are two different files and normalizing to NFC can turn a legitimate lookup into a miss. Normalize to compare a name against an allowlist; do not assume the normalized form is what is on disk
- `resolve(strict=True)` raises for a missing target, which suits a read; for a write destination resolve the *parent* instead, since the destination does not exist yet. Non-strict `resolve()` appends the unresolved remainder unchanged, so its result "may still contain links or loops"
- Confirm the target with `is_file()` before serving, so directories and special files are refused

## Taint Sinks

`open()`, `send_file()`, `os.remove()`, `shutil.copy()`, `os.path.join()` with unvalidated input, `os.listdir()`

## Remediation Steps

- Locate - find path comparisons or sanitizers (`replace('../', '')`, `'..' in path`, `startswith`) applied to `request.args`, `request.form`, or a path parameter
- Trace data flow - follow the value through every join to the check and then to the file operation, confirming the checked value and the opened value are the same variable
- Replace the unsafe pattern - reject an absolute input, build the candidate against the resolved base, call `resolve(strict=True)`, then verify `is_relative_to(ALLOWED_DIR)`
- Bind, encode, validate, or authorize - reject null bytes and separators where a bare filename is expected, and apply an extension allowlist where only certain types are legitimate
- Break taint after allowlist validation - pass the resolved path to the sink, never the raw request value
- Harden configuration - prefer `flask.send_from_directory()` or Django's `FileSystemStorage` over a hand-rolled check, with two caveats. Flask's containment is Werkzeug's `safe_join`, whose operative floor is **3.1.6**: CVE-2024-49766 (fixed 3.0.6) then three Windows device-name escapes, of which CVE-2026-21860 (3.1.5) and CVE-2026-27199 (3.1.6) are documented as bypasses of the previous fix. Django's lives in the private `django.utils._os.safe_join`, and CVE-2024-39330 shows a `Storage` subclass that overrides `generate_filename()` loses it. Both are lexical and neither resolves symlinks
- Test - assert equivalent spellings (`dir`, `dir/`, `dir/.`, `dir//`) reach the same decision, that `....//`, an absolute input, and a symlink out of the base are all refused, and that a legitimate file still downloads
