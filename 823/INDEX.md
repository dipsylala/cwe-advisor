# CWE-823: Use of Out-of-range Pointer Offset

## LLM Guidance

Use of out-of-range pointer offset occurs when pointer arithmetic uses an offset that can place the resulting pointer outside the buffer it was meant to reference, typically from unchecked indexing, an off-by-one loop bound, or an offset derived from external input without validation. Once formed, dereferencing that pointer produces an out-of-bounds read or write. The fix is to validate any offset against the buffer's actual bounds before the pointer is formed, and to prefer bounds-checked accessors over hand-computed pointer arithmetic.

## Key Principles

- Validate an offset against the buffer's real size before forming the pointer, not after it has been dereferenced
- Check both the offset and, where arithmetic could wrap, the resulting pointer value against the buffer's valid range
- Prefer bounds-checked containers, spans, or accessor functions that reject an out-of-range offset over raw pointer arithmetic
- Use strict less-than comparisons against the element count in loop bounds, and consistent unsigned index types checked for wraparound before use
- Never trust an offset or index taken from user input, file data, or network data without validating it against the actual buffer size
- Enable compiler warnings for pointer-arithmetic issues as build failures, and use sanitizers and fuzzing in development as defence-in-depth

## Remediation Steps

- Locate - Identify pointer arithmetic expressions, pointer plus offset, and the dereference or write that follows
- Trace data flow - Follow the offset or index value back to its source to determine whether it comes from external input or an unvalidated calculation
- Identify the unsafe pattern - Look for pointer arithmetic performed before any check that the offset falls within the buffer's bounds
- Replace with the safe pattern - Add an explicit range check on the offset before the arithmetic, or replace hand-computed pointer arithmetic with a bounds-checked span or accessor
- Add secondary controls - Fix related loop and index boundary conditions and enable pointer-arithmetic warnings as build failures
- Test - Exercise offsets at, one below, and one above the buffer boundary, plus negative and overflow-inducing values, and confirm each is rejected before the pointer is used
