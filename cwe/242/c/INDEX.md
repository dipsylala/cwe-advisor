# CWE-242: Use of Inherently Dangerous Function - C

## LLM Guidance

`gets()` is the standard library's example of a function with no safe calling convention: it takes no argument for the destination's size, so it cannot stop even a careful caller from writing past the end of the buffer. It was removed from C11 - removed, not deprecated - so any remaining call is replaced rather than guarded. The direct replacement is `fgets(buf, sizeof buf, stdin)`, which takes the capacity as a required argument.

## Key Principles

- Replace `gets()` with `fgets()`, which enforces the bound through its own contract rather than depending on a caller-side check
- `fgets()` also distinguishes failure from an empty read - it returns `NULL` at end of file with nothing consumed, or on error - which `gets()` never allowed the caller to tell apart
- A non-`NULL` return does not mean a whole line was read: on an over-long line `fgets` fills the buffer, stops, and returns exactly as it would for a short line, leaving the remainder in the stream to be read as though it were the next line. Detect that by the missing trailing `'\n'` and drain to the next newline
- Strip the newline with `buffer[strcspn(buffer, "\n")] = '\0'` rather than assuming it is present
- Make reintroduction a build error where possible (a header that `#define`s the banned name to something that fails to compile, or a lint rule), so the fix cannot be silently undone
- The same class covers other unbounded functions - `strcpy`, `strcat`, `sprintf`, `scanf("%s")` - whose replacements are on CWE-121 and CWE-787
- In C++, `std::cin >> buf` has three states depending on the standard: bounded for an array destination under C++20 and later (the overload takes `CharT (&)[N]`), unbounded for either shape under C++17 and earlier, and ill-formed for a `char *` destination under C++20+, since P0487R1 replaced the pointer overload rather than adding beside it. Check the translation unit's actual `-std` flag rather than the project's stated baseline; `std::setw(sizeof buf)` bounds it on older standards, and a `std::string` destination avoids the question

## Taint Sinks

`gets()`, `scanf("%s", ...)` without a field width, `strcpy()`, `strcat()`, `sprintf()`, `std::istream::operator>>` into a character buffer

## Remediation Steps

- Locate - grep for the banned functions across the codebase, not only at the line the finding names
- Trace data flow - confirm which destination buffer each call writes into and what its real capacity is
- Identify the unsafe pattern - a call whose signature has no way to receive the destination's size
- Replace with the safe pattern - `fgets` for line input, `snprintf` for formatting, and an explicit length check before `memcpy`
- Bind, encode, validate, or authorize - treat a truncated read as invalid input: drain the rest of the line and reject, rather than processing the fragment
- Harden configuration - add a lint or compiler-diagnostic rule so a new call fails the build, and enable `-Wall -Wextra -D_FORTIFY_SOURCE=2` at `-O1` or higher
- Test - feed a line longer than the buffer and assert the input is rejected and the remainder is not parsed as a second line; feed EOF with no data and assert the failure path is taken
