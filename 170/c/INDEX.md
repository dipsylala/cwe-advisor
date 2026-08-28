# CWE-170: Improper Null Termination - C

## LLM Guidance

A C string is a byte array with no stored length, so every function that treats a `char *` as a string - `strlen`, `strcmp`, `printf("%s", ...)` - scans forward until it finds a `\0`. A buffer missing that byte, or carrying it in the wrong place, makes those functions read past the buffer's real end. The two recurring causes are `strncpy()`, which writes no terminator when the source is at least as long as the destination, and raw reads (`recv()`, `read()`, `fread()`) that return only the bytes transferred.

## Key Principles

- After `strncpy(dest, src, sizeof(dest) - 1)`, always write `dest[sizeof(dest) - 1] = '\0'` - the copy bound leaves that byte untouched so the assignment always lands inside the buffer
- That fixed-offset terminator is safe specifically because `strncpy` zero-pads a short source. A primitive that truncates without padding (`memcpy` with a computed length) leaves stale bytes between the copied data and the last index, so terminate at the number of bytes actually copied instead
- `recv()`/`read()` never terminate: read at most `sizeof(buf) - 1` and write `buf[bytes_read] = '\0'`, positioning the terminator at the end of the data actually received rather than at a fixed offset
- Guard that write with `if (bytes_read < 0) return;`, not `if (bytes_read > 0)` - `recv()` returns 0 when the peer closes, and a `> 0` guard skips the terminator on exactly that path, leaving the buffer as unterminated as before the fix
- One `recv()` is not one message: it returns whatever has arrived, so a caller needing a whole line or a length-prefixed frame must loop and terminate after the last byte of the accumulated data
- Allocate `strlen(src) + 1` bytes, counting the terminator, whenever a string is copied into fresh memory
- Bound a loop that rewrites string bytes with `i < len`, so index `len` - the terminator's position - is never written whatever the loop body later becomes
- Use `strnlen(buf, cap)` rather than `strlen(buf)` on any buffer whose termination is not guaranteed, and treat a result equal to `cap` as invalid data rather than a string

## Taint Sinks

`strncpy()`, `strncat()`, `recv()`, `read()`, `fread()`, `memcpy()` into a buffer later used as a string, `snprintf()` return value ignored

## Remediation Steps

- Locate - find `strncpy` calls, raw socket/file reads, and any buffer filled by a non-string primitive that is later passed to a string function
- Trace data flow - follow the buffer from the fill to every use as a string, and identify whether a terminator is written on all paths, including the error and zero-byte paths
- Identify the unsafe pattern - a copy sized at exactly the destination's capacity, a read whose return value is not used to place a terminator, or an allocation of `strlen(src)` without the extra byte
- Replace with the safe pattern - reserve the final byte, terminate explicitly at the count actually written, and size allocations as `len + 1`
- Bind, encode, validate, or authorize - where the source may legitimately exceed the destination, reject the input rather than relying on a silent truncation the caller cannot detect
- Harden configuration - build with `-Wall -Wextra` and `-D_FORTIFY_SOURCE=2` at `-O1` or higher, and run tests under `-fsanitize=address`
- Test - exercise a source exactly as long as the destination, a source one byte longer, a zero-byte read from a closed peer, and a read error; confirm under ASan that no read runs past the buffer
