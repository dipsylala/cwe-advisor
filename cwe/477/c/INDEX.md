# CWE-477: Use of Obsolete Function - C

## LLM Guidance

This is about the *status* of the function: withdrawn from the C standard or from POSIX, not merely easy to misuse. `gets()` was removed in C11; `tmpnam()`/`tempnam()` have a race baked into the API; `getwd()`, `bcopy()` and `bzero()` were dropped from POSIX.1-2008. Compilers keep accepting them for compatibility, so they compile and run long after the standard stopped listing them. Replace each with its named successor.

## Key Principles

- `gets()` to `fgets(buf, sizeof buf, stdin)`, then strip the retained newline with `buf[strcspn(buf, "\n")] = '\0'`; `NULL` means end of file or error rather than empty input
- `tmpnam()`/`tempnam()`/`mktemp()` to `mkstemp()`/`mkdtemp()`, which create the file atomically - the obsolete forms return a *name*, and anything can claim it before you open it; `mkstemp()` rewrites the `XXXXXX` suffix of a writable template, so `unlink()` it straight away and keep only the descriptor
- `getwd()` to `getcwd(buf, size)`, which takes the buffer's capacity; `bcopy(src, dst, n)` to `memmove(dst, src, n)`, not `memcpy` - the argument order reverses (`bcopy` takes source first) and `bcopy` tolerates overlapping regions, which `memcpy` does not; `bzero()` to `memset()`, and where the intent is to erase a secret use `explicit_bzero()` (glibc 2.25+, BSD) or C23's `memset_explicit()`, since a plain `memset` can be optimised away - `memset_s()` is optional C11 Annex K, which glibc does not implement, so do not offer it as a fallback
- `strcpy()`, `strcat()` and `sprintf()` are *not* obsolete - they are current standard C with a documented safe calling convention, so a scanner filing them here has the wrong CWE; they belong to CWE-676 (or CWE-121/CWE-787 when a specific overflow is found)
- Check `mkstemp()`'s return value before using it: falling through to `fdopen(-1, "w")` on an unchecked failure is not a degraded mode, it hands the rest of the function a NULL `FILE*` that the next write dereferences
- `rand()`/`srand()` are likewise current and correct for anything that does not need unpredictability; using one for a token, key, or session identifier is CWE-338, and whether it is a finding depends on what predicting the value would give an attacker
- Where the successor is not portable (`strlcpy` is BSD, macOS, and glibc 2.38+), guard it or use `snprintf` as the portable bounded form
- Add a compile-time guard - a poisoned identifier (`#pragma GCC poison gets`) or a lint rule - so a replaced function cannot be reintroduced silently

## Taint Sinks

`gets()`, `tmpnam()`, `tempnam()`, `mktemp()`, `getwd()`, `bcopy()`, `bzero()`, `usleep()` (obsolescent since POSIX.1-2001, replace with `nanosleep()`), `gethostbyname()` (superseded by `getaddrinfo()`, which handles IPv6 and multiple addresses)

## Remediation Steps

- Locate - grep for the withdrawn functions across the whole tree, not only the line the finding names
- Trace data flow - for each call, identify the buffer it writes into and its real capacity, since the replacement takes a size the original did not
- Identify the unsafe pattern - a function no longer in the standard or POSIX, distinguished from one that is merely easy to misuse
- Replace with the safe pattern - the named successor, passing the destination's capacity, and check the return value
- Bind, encode, validate, or authorize - treat a truncated read or write as invalid input rather than continuing with the fragment
- Harden configuration - poison the identifiers or add a lint rule so reintroduction fails the build, and build with `-Wall -Wextra -D_FORTIFY_SOURCE=3` at `-O2` or higher (GCC 12+ with glibc 2.35+, or Clang 9+ with glibc 2.33+; fall back to `=2` on older toolchains)
- Test - exercise oversized input on each replaced call under `-fsanitize=address` and confirm it is rejected rather than truncated silently; confirm temporary files are created with `O_EXCL` semantics. A statistical test suite (`dieharder` and similar) proves nothing about a `rand()`-replacement's suitability as a CSPRNG - `rand()` itself passes most of them; state-recovery resistance is the property that matters, and that is a CWE-338 question, not this one
