# CWE-367: Time-of-check Time-of-use Race Condition - C

## LLM Guidance

A filesystem call takes a path, and the kernel resolves that path again on every call. Two calls naming the same path are two separate lookups, and between them another process can replace the file - or any directory on the way to it - typically with a symbolic link. That is why `access()` then `open()`, or `stat()` then `open()`, is a defect regardless of how little code sits between them: the window is the interval between two syscalls, and an attacker retrying in a loop only has to win it once. Open first, then check the descriptor.

## Key Principles

- Resolve the path once: `open()` first, then `fstat()`/`fchown()`/`fchmod()` on the descriptor, so every later check refers to the file you actually opened
- Never use `access()` to decide whether to open something - it checks the real UID's permissions at that instant against a name, which is both the wrong question and a separate lookup
- Pass `O_NOFOLLOW` so the final component cannot be a symlink, and `O_NONBLOCK` so a FIFO or device node cannot make `open()` itself hang
- Use `O_CREAT | O_EXCL` with mode `0600` when creating a file, so an attacker-planted name is refused rather than followed or truncated
- For a path with untrusted directory components, hold a descriptor for the base directory and use the `*at()` family (`openat`, `fstatat`, `unlinkat`) with `AT_SYMLINK_NOFOLLOW`, which resolves relative to that descriptor instead of re-walking the whole path
- Check `S_ISREG(st.st_mode)` on the descriptor before reading, so a device node or directory is refused
- Temporary files go through `mkstemp()`/`mkdtemp()`, never `tmpnam()`/`mktemp()`, which return a name that anything can claim before you open it
- Where the check is about ownership, compare `st.st_uid` from `fstat()` on the open descriptor, not from a `stat()` on the path

## Taint Sinks

`access()` followed by `open()`, `stat()`/`lstat()` followed by `open()`, `chmod()`/`chown()` on a path, `unlink()` after a check, `tmpnam()`/`mktemp()`, `rename()` guarded by an existence test

## Remediation Steps

- Locate - find pairs of filesystem calls that name the same path, where the first decides whether the second runs
- Trace data flow - determine whether any component of the path is in a directory writable by another user (`/tmp`, an upload directory, a user home)
- Identify the unsafe pattern - a check on a path followed by an operation on the same path, rather than on a descriptor
- Replace with the safe pattern - open once with `O_NOFOLLOW | O_NONBLOCK` (plus `O_CREAT | O_EXCL` for creation) and perform every check with `fstat`/`fchmod`/`fchown` on the descriptor
- Bind, encode, validate, or authorize - use `openat` and the `*at()` family against a held directory descriptor when intermediate components are untrusted
- Harden configuration - keep the directory unwritable by other users where possible; that removes the attacker's ability to swap components at all
- Test - run the operation in a loop against a helper that repeatedly replaces the target with a symlink, and assert the operation fails rather than following it
