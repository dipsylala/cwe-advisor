# CWE-191: Integer Underflow (Wrap or Wraparound)

## LLM Guidance

Integer underflow occurs when a subtraction (or other arithmetic) produces a result below the minimum value its type can represent. An unsigned type wraps to a very large positive value instead of going negative, most often from an unvalidated "remaining space" or "count minus offset" calculation where the subtrahend can legitimately exceed the minuend. When the wrapped value sizes a buffer, a copy, or a loop bound, it drives out-of-bounds access or memory corruption in native code, and wrong results or unhandled exceptions in managed languages. The fix is to validate that a subtraction cannot cross the type's minimum before performing it, never after.

## Key Principles

- Check that the minuend is at least as large as the subtrahend before subtracting; never inspect the result afterward, since by then it has already wrapped
- Prefer a language or library's checked-arithmetic primitive so an underflow throws or is caught rather than silently wrapping
- Reserve unsigned types for values that are logically never negative, and enforce that invariant at every arithmetic site; use a signed type when in doubt
- Never write reverse iteration with an unsigned loop counter compared against zero with a non-strict operator; when the count reaches zero, the decrement wraps and the comparison is always true
- Treat a length or count value that travels with untrusted data as unvalidated, not as a trustworthy bound, even if it arrived alongside the data it describes
- Managed-language bounds checking prevents memory corruption from a wrapped value but not the underlying logic error; an unhandled exception from it is still a denial-of-service

## Remediation Steps

- Locate - Find subtractions (and reverse-iteration loop bounds) where at least one operand is influenced by user input, a file, or a network message
- Trace data flow - Identify the source of both operands and what consumes the subtraction's result (allocation size, copy length, loop bound, array index)
- Identify the unsafe pattern - No check that the minuend is at least as large as the subtrahend before the subtraction runs
- Replace with the safe pattern - Add a pre-check that rejects or clamps when the subtrahend would exceed the minuend, or use a checked-arithmetic primitive
- Fix reverse iteration - Rewrite unsigned reverse loops so the decrement happens inside the loop condition, never compared against zero after wraparound is possible
- Add secondary controls - Bounds-check the eventual index or length immediately before use, independent of the earlier arithmetic
- Test - Verify with the subtrahend equal to and one greater than the minuend, a count of zero feeding a reverse loop, and maximum representable values for the type
