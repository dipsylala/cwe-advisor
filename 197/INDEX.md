# CWE-197: Numeric Truncation Error

## LLM Guidance

This weakness appears when a value is cast or assigned from a wider numeric type to a narrower one, such as a 64-bit size into a 32-bit field, a large integer into a smaller one, or a floating-point value into an integer, and the destination type cannot represent the original value. The high-order bits or fractional/out-of-range magnitude are silently discarded rather than raising an error, producing a value unrelated to the original one; this is especially dangerous when the narrowed value is later used for an allocation or bounds check while other code still uses the original, wider value. The fix is to validate the value against the destination type's range while it is still in the wider type, before the narrowing conversion, and to reject or resize rather than convert implicitly.

## Key Principles

- Primary defence: validate that a value fits within the destination type's minimum/maximum before narrowing it; never allow an implicit, unchecked narrowing conversion.
- For floating-point-to-integer conversions, also reject NaN and infinity before converting; both produce undefined or implementation-defined results.
- Never rely on a post-conversion check; the information needed to detect an out-of-range value (the original wide value) is already gone once the value has been narrowed.
- Use the same validated, narrowed value consistently for every downstream operation (allocation and copy/write) so no operation is sized differently from another.
- Prefer storing values that can legitimately grow large (timestamps, file sizes, counts) in a sufficiently wide type from the start rather than narrowing later "to save space."
- Defence-in-depth: enable and enforce compiler warnings for narrowing and floating-point conversion so future regressions fail the build.

## Remediation Steps

- Locate - Find every place a wider-typed value is cast or assigned into a narrower type, especially where the result feeds a buffer size, array index, struct field, or downstream calculation.
- Trace data flow - Follow the value from its source (a wide-typed size, timestamp, or floating-point result) to the sink where the narrowing conversion occurs and to everywhere the narrowed value is subsequently used.
- Identify the unsafe pattern - Confirm there is no explicit range check against the destination type's minimum/maximum (and, for floating point, no NaN/infinity check) before the cast.
- Replace with the safe pattern - Add an explicit range check on the wide value before narrowing, rejecting or clamping values that do not fit, and use the same validated value for every subsequent operation.
- Avoid narrowing where possible - Store the value in a sufficiently wide type for its full lifetime instead of narrowing it at all.
- Add secondary controls - Enable compiler warnings/static analysis for narrowing and floating-point conversion and treat them as build failures.
- Test - Exercise each narrowing path with the destination type's minimum, maximum, one value above the maximum, and a value with high-order bits set, confirming out-of-range values are rejected before narrowing.
