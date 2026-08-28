# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Python

## LLM Guidance

Path Traversal in Python starts with a request value reaching `open()`, `send_file()`, `shutil.copy()` or an archive extractor after being joined to a base directory. Both joining APIs discard the base when the second segment is absolute - `os.path.join('/srv/data', '/etc/passwd')` and `Path('/srv/data') / '/etc/passwd'` both return `/etc/passwd`, and neither raises. The fix is to resolve the joined path with `Path.resolve()` and confirm containment with `is_relative_to()` before opening anything, or better, to map an identifier to a path so no request value reaches the filesystem at all.

## Key Principles

- Prefer indirect reference mapping; where the path must come from input, resolve then check containment, in that order
- `os.path.normpath()` and `os.path.abspath()` are not sanitizers - neither makes a filesystem call, so neither sees a symbolic link; only `Path.resolve()` and `os.path.realpath()` do
- Normalizing before the join leaves a leading `..` intact for the join to apply; normalizing after the join produces a clean absolute path that points outside the base and no longer contains `..` for a substring check to find. Neither ordering is a containment check
- Use `Path.is_relative_to()` (3.9+) rather than `str(path).startswith(str(base))` - a string prefix has no notion of a path component, so `/srv/app/documents-archive` matches a base of `/srv/app/documents`
- Reads and writes differ by `strict=`: `resolve(strict=True)` raises `FileNotFoundError` for a path that does not exist, which is correct for a download and wrong for an upload destination. For a write, resolve the *parent*, reject a filename containing `/`, `\`, or equal to `''`/`.`/`..`, and create with `os.O_WRONLY | os.O_CREAT | os.O_EXCL` so an existing file or planted symlink is refused rather than overwritten - without an access mode the descriptor opens read-only and the write fails
- Reject rather than strip: `Path(name).name` and `secure_filename()` contain the traversal but hide the attempt from the audit log and collapse two hostile inputs onto one filename
- In web code prefer the framework's own containment helper - `flask.send_from_directory()` (which applies `werkzeug.utils.safe_join()` and returns 404 on rejection) or Django's `FileSystemStorage` (which raises `SuspiciousFileOperation`) - over rebuilding the check
- Containment is not authorization: confirming a path is inside the upload directory says nothing about whether this user may read that file

## Taint Sinks

`open()`, `os.remove()`, `shutil.copy()`, `shutil.move()`, `send_file()`, `tarfile.extractall()`, `ZipFile.namelist()` joined manually (Zip Slip)

## Remediation Steps

- Locate - find where `request.args`, `request.form`, `request.files`, path parameters, or archive member names reach a file operation
- Trace data flow - follow the value through every `os.path.join()`/`/` operation and helper function; the value that was checked must be the value that is opened
- Replace the unsafe pattern - resolve the joined path once into a variable with `Path.resolve()`, verify `candidate.is_relative_to(BASE_DIR)`, confirm `is_file()`, and pass that variable to `open()`
- Bind, encode, validate, or authorize - for writes, validate the filename is a single component and resolve the parent instead of the destination; add an ownership check where files belong to accounts
- Break taint after allowlist validation - use the resolved path or the map's value at the sink, never the raw request value
- Harden configuration - extract tar archives with `tarfile.extractall(dest, filter='data')` (available 3.12+, default from 3.14); on 3.11 and earlier, filter members individually against a resolved destination. `ZipFile.extractall()` already sanitizes member names - the exposure there is code that reads `namelist()` and joins the names itself
- Test - assert a legitimate subdirectory read still succeeds, that both `../../etc/passwd` and `/etc/passwd` raise (they take different routes through the code), that a sibling directory such as `../documents-archive/notes.txt` raises, and that a traversing upload name raises rather than being silently reduced
