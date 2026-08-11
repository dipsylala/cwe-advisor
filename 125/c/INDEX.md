# CWE-125: Out-of-bounds Read - C

## LLM Guidance

In C, out-of-bounds reads arise from raw pointer arithmetic and array indexing that trust an index, offset, or length without checking it against the buffer's real, allocated size. The highest-risk sinks are `memcpy()`, `read()`, and `sscanf()` (and similar copy/scan functions) when their size argument comes from attacker-controlled input or a miscalculated offset-plus-length sum. Prefer explicit length tracking and bounds-checked accessors over trusting a length embedded in the data itself, and use `strnlen()` rather than `strlen()` on any buffer that is not guaranteed to be NUL-terminated within its allocated size. Pair manual bounds checks with compiler and runtime hardening (`-fsanitize=address,undefined`, `_FORTIFY_SOURCE`) to catch what a manual check misses.

## Key Principles

- Track buffer capacity explicitly alongside every pointer; never assume a length from a fixed-size type or a convention such as NUL-termination
- Validate `offset <= buffer_size` first, then `length <= buffer_size - offset`, in that order, so the subtraction cannot underflow
- Use `strnlen(buf, cap)` instead of `strlen(buf)` on any buffer received from input, network, or file data - `strlen` reads past the end if no NUL terminator is present within the buffer
- Check every array index against the array's known bound (`0 <= index < length`) immediately before the dereference, not in a distant caller
- Never pass an attacker-supplied or miscalculated size directly to `memcpy()`, `read()`, or an `sscanf()` field width; clamp it against both the source's actual available bytes and the destination's capacity first
- Compile with `-fsanitize=address,undefined` in testing and `-D_FORTIFY_SOURCE=2` (with `-O1` or higher) in production builds as defence-in-depth

## Taint Sinks

`memcpy()`, `memmove()`, `read()`, `sscanf()`, array indexing/pointer arithmetic with unvalidated offset or length

## Remediation Steps

- Locate - Search for pointer arithmetic, array indexing, and calls to `memcpy()`, `memmove()`, `read()`, `sscanf()`, and similar copy/scan functions
- Trace data flow - Identify where the index, offset, or length operand originates (network, file, CLI, prior calculation) and whether the buffer's actual size is known at that point
- Identify the unsafe pattern - A read, copy, or scan whose size, offset, or index is used without validation against the real buffer size, or validated only after the read
- Replace with the safe pattern - Add an explicit, underflow-safe bounds check before the read, or use `strnlen()`/a bounds-checked helper that enforces the buffer's capacity
- Bind, encode, validate, or authorize - Clamp the length or offset to the smaller of the source's available bytes and the destination's capacity before calling `memcpy`/`read`/`sscanf`
- Harden configuration - Build and test with `-fsanitize=address,undefined`; enable `-D_FORTIFY_SOURCE=2` with `-O1` or higher in release builds
- Test - Test with oversized, negative, and boundary index/offset/length values, and with non-NUL-terminated buffers filled to exactly their allocated capacity

## Safe Pattern

```c
#include <string.h>
#include <stdint.h>
#include <stddef.h>

// SAFE: validate offset and length against the buffer's actual received
// size before reading; claimed_len is attacker-controlled, buf_len is the
// true number of bytes available in buf
int extract_payload(const uint8_t *buf, size_t buf_len, size_t offset,
                     size_t claimed_len, uint8_t *out, size_t out_cap) {
    if (offset > buf_len)
        return -1;
    size_t available = buf_len - offset;
    if (claimed_len > available || claimed_len > out_cap)
        return -1; // reject: would read past buf or write past out

    memcpy(out, buf + offset, claimed_len);
    return 0;
}

// SAFE: bound a scan length instead of trusting a NUL terminator in
// untrusted memory
size_t safe_len = strnlen(untrusted_buf, untrusted_cap);
if (safe_len == untrusted_cap)
    return -1; // no terminator found within the buffer; treat as invalid
```
