# CWE-135: Incorrect Calculation of Multi-Byte String Length - C

## LLM Guidance

C has no native notion of characters for multi-byte or wide-character encodings: `strlen()` counts bytes to the first NUL, and indexing offsets to raw bytes or `wchar_t` elements. Code that mixes byte counts with character counts - UTF-8 text, or Windows `WCHAR`/`TCHAR` buffers - miscounts, producing undersized allocations, copies that split a multi-byte sequence, and overflows where a byte count was used as an element count. The recurring concrete instance is Win32 API misuse, where `MultiByteToWideChar`/`WideCharToMultiByte` take element counts and callers pass byte counts.

## Key Principles

- Track the byte length and the character count as separate variables and never substitute one for the other: allocate and `memcpy` by bytes, enforce user-facing limits by characters
- `strlen()` and `sizeof(char[])` are byte counts; a real character count requires decoding the encoding (a UTF-8 decode loop, or ICU's `u_countChar32` after conversion)
- `wcslen()` counts `wchar_t` elements, and `wchar_t` is 16 bits on Windows and 32 bits on most Unix platforms - so an element count is not a byte count and is not a character count either, since a UTF-16 surrogate pair is two elements and one character
- `MultiByteToWideChar`/`WideCharToMultiByte` take and return counts in *elements* for the wide side and *bytes* for the narrow side; call once with `CP_UTF8` and a zero size to obtain the required count rather than assuming a ratio, passing a source length of `-1` for NUL-terminated input so the returned count already includes the terminator - only pass `-1` when the source is actually NUL-terminated, since the function reads until it finds one and a fixed-size buffer of raw bytes (e.g. from a network read) that isn't will be over-read
- A byte count used as a character-count limit is never an overflow risk in UTF-8, since a byte count is never smaller than the corresponding character count - it only over-rejects short-looking input, which surfaces as a usability complaint rather than a security bug. The overflow-prone direction is a character count (or code point count) used to size a byte allocation, which is too small whenever any multi-byte character is present
- The `+1`-for-the-terminator rule applies only to a count from `strlen()`/`wcslen()` or a positive size argument, both of which exclude the terminator - allocate `bytes + 1`, or for wide strings `(elements + 1) * sizeof(wchar_t)`. Don't add it again on top of the zero-size/`-1` query result above, which already counts the terminator; doing so over-allocates by one element, not a security bug but a sign the two counting conventions got mixed
- Truncating by bytes splits a multi-byte sequence and produces invalid text; truncate on a character boundary or reject the over-long input outright
- Do not assume a fixed bytes-per-character ratio: UTF-8 code points are 1-4 bytes, and a user-perceived character may be several code points
- Validate that untrusted input is well-formed for its declared encoding before measuring it, since an invalid sequence makes any count meaningless

## Taint Sinks

`strlen()`/`wcslen()` used as a character count, `malloc()` sized from the wrong unit, `memcpy()`/`strncpy()` with a mismatched count, `MultiByteToWideChar()`/`WideCharToMultiByte()` size arguments, `substr`-style byte slicing

## Remediation Steps

- Locate - find length calculations applied to text that can contain non-ASCII data, and every Win32 conversion call
- Trace data flow - determine which unit each variable holds (bytes, `wchar_t` elements, characters) and where one is passed where another is expected
- Identify the unsafe pattern - a byte count used as a character count or element count, an allocation missing the terminator, or a truncation on a byte boundary
- Replace with the safe pattern - keep both counts, size allocations from the byte count, and enforce limits from a decoded character count
- Bind, encode, validate, or authorize - query the required size from the conversion API with a zero size argument rather than computing it, and reject input that is not valid for its encoding
- Harden configuration - build with `-Wall -Wextra` and test under `-fsanitize=address`, which catches the undersized-allocation case
- Test - pass text containing 2-, 3- and 4-byte UTF-8 sequences, a UTF-16 surrogate pair, and a truncated sequence, and assert lengths, allocations, and truncation boundaries are correct
