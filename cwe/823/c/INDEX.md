# CWE-823: Use of Out-of-range Pointer Offset - C

## LLM Guidance

This appears as pointer arithmetic (`ptr + offset`, `ptr++`) or array indexing (`array[i]`) where the offset is not validated against the buffer's real size before use. C bounds-checks nothing, so the unchecked offset silently produces a pointer into memory that was never part of that allocation. Validate the offset as *integer* arithmetic before the pointer is formed. Where the finding is really about a copy function writing past a destination, it is CWE-787 or CWE-121 instead, and those carry the replacement functions.

## Key Principles

- Check `if (offset >= size) reject;` rather than `if (buffer + offset >= buffer + size) reject;` - forming a pointer more than one past the end is already undefined behaviour, so a comparison written to detect it can legally be optimised away
- Test the sign explicitly (`offset < 0`) as well as the magnitude. With a `size_t` size the comparison would convert a negative offset to a huge unsigned value and reject it anyway, but that behaviour depends on the *other* operand's type, which is usually declared in another file - stating the precondition keeps the function correct if `size` later becomes `int` or `long`
- Never let a signed value reach a bounds comparison without either testing its sign or knowing which way the conversion goes
- Keep the size with the pointer: pass `(buffer, size)` together and validate inside the callee rather than trusting a length the caller supplied separately
- Validate `offset <= size` first and then `length <= size - offset`, in that order, so the subtraction cannot underflow
- Loop with `for (size_t i = 0; i < count; i++)` - `<=` writes one element past the end of every buffer the function touches
- Build tests with `-fsanitize=address,undefined`, which reports the out-of-bounds access and the pointer-overflow separately; also compile and run the check itself at `-O2`, not only `-O0` - a guard written against an already-out-of-range pointer can pass at `-O0` and disappear once the compiler is allowed to exploit the undefined behaviour it depends on

## Taint Sinks

`ptr + offset` / `ptr[i]` with an unvalidated offset, `memcpy()`/`memmove()` destination or source computed by arithmetic, `*ptr++` loops, `&array[i]` passed onward

## Remediation Steps

- Locate - find pointer arithmetic and array indexing whose offset is not a compile-time constant
- Trace data flow - identify where the offset originates (a parsed header field, an index from a request, a computed difference) and whether the buffer's real size is known at that point
- Identify the unsafe pattern - a pointer formed before the offset is checked, a check written on the formed pointer, or a loop bounded with `<=`
- Replace with the safe pattern - validate the integer offset against the size, then form the pointer, then use it
- Bind, encode, validate, or authorize - clamp or reject an offset that exceeds the buffer, and pass the size alongside the pointer through every layer
- Harden configuration - build with `-Wall -Wextra -D_FORTIFY_SOURCE=3` at `-O1` or higher (needs GCC 12+ with glibc 2.35+, or Clang 9+ with glibc 2.33+; fall back to `=2` on older toolchains) and test under `-fsanitize=address,undefined`
- Test - pass offsets of `-1`, `0`, `size - 1`, `size`, and a very large value, and confirm the out-of-range ones are refused rather than clamped silently; also confirm `offset == size` with a zero length is accepted - that is a legitimate empty read, not a boundary to reject
