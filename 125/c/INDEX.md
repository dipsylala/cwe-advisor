# CWE-125: Out-of-bounds Read - C

## LLM Guidance

In C, out-of-bounds reads arise from raw pointer arithmetic and array indexing that trust an index, offset, or length without checking it against the buffer's real, allocated size. The highest-risk sinks are `memcpy()`/`memmove()`, the string functions (`strlen()`, `strcmp()`, `strchr()`) applied to a buffer with no NUL inside its allocation, and `write()`/`send()` asked to transmit more than was actually received. Note the direction: `read()` writes into its buffer, so an oversized length there is CWE-787 rather than this weakness. Prefer explicit length tracking and bounds-checked accessors over trusting a length embedded in the data itself, and use `strnlen()` rather than `strlen()` on any buffer that is not guaranteed to be NUL-terminated within its allocated size. Pair manual bounds checks with compiler and runtime hardening (`-fsanitize=address,undefined`, `_FORTIFY_SOURCE`) to catch what a manual check misses.

## Key Principles

- Track buffer capacity explicitly alongside every pointer; never assume a length from a fixed-size type or a convention such as NUL-termination
- Validate `offset <= buffer_size` first, then `length <= buffer_size - offset`, in that order, so the subtraction cannot underflow
- Test the sign while the value is still signed. A check written as `(size_t)offset + length <= buffer_size` converts `offset == -1` into `SIZE_MAX`, the sum wraps back into range, the check passes, and the read lands far outside the buffer - reject a negative offset before any conversion to an unsigned type
- Use `strnlen(buf, cap)` instead of `strlen(buf)` on any buffer received from input, network, or file data - `strlen` reads past the end if no NUL terminator is present within the buffer, and a `strnlen` result equal to `cap` means no terminator was found, so reject the buffer rather than reading on
- Check every array index against the array's known bound (`0 <= index < length`) immediately before the dereference, not in a distant caller
- Never pass an attacker-supplied or miscalculated size directly to `memcpy()` or `memmove()`; clamp it against both the source's actual available bytes and the destination's capacity first
- An `sscanf()` field width cannot be clamped at run time: C has no dynamic field width, and `%*s` means suppress assignment rather than take the width from an argument. Write a literal width one smaller than the destination (`%99s` for a `char[100]`), and confirm the source is NUL-terminated inside its own allocation before scanning it
- Compile with `-fsanitize=address,undefined` in testing and `-D_FORTIFY_SOURCE=3` (with `-O1` or higher) in production builds as defence-in-depth - level 3 adds checks for sizes only known at run time, where level 2 covers only what the compiler can size statically; it needs GCC 12+ or Clang 15+, so fall back to `=2` on older toolchains
- Guard the size arithmetic itself: `if (count > SIZE_MAX / sizeof(T))` before multiplying, since a wrapped product produces a bound that is smaller than the data it is meant to describe

## Taint Sinks

`memcpy()`, `memmove()`, `strlen()`/`strcmp()`/`strchr()`/`printf("%s")` on a buffer with no NUL inside its allocation, `write()`/`send()` with a length larger than what was received, `sscanf()`, array indexing/pointer arithmetic with unvalidated offset or length

## Remediation Steps

- Locate - Search for pointer arithmetic, array indexing, calls to `memcpy()`/`memmove()`, `str*` calls on buffers filled from input, and `write()`/`send()` whose length is not the count actually received
- Trace data flow - Identify where the index, offset, or length operand originates (network, file, CLI, prior calculation) and whether the buffer's actual size is known at that point
- Identify the unsafe pattern - A read, copy, or scan whose size, offset, or index is used without validation against the real buffer size, or validated only after the read
- Replace with the safe pattern - Add an explicit, underflow-safe bounds check before the read, or use `strnlen()`/a bounds-checked helper that enforces the buffer's capacity
- Bind, encode, validate, or authorize - Clamp the length or offset to the smaller of the source's available bytes and the destination's capacity before calling `memcpy`/`memmove`, and use a literal field width for `sscanf`
- Harden configuration - Build and test with `-fsanitize=address,undefined`; enable `-D_FORTIFY_SOURCE=3` with `-O1` or higher in release builds
- Test - Test with oversized, negative, and boundary index/offset/length values, and with non-NUL-terminated buffers filled to exactly their allocated capacity
