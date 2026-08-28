# CWE-195: Signed to Unsigned Conversion Error

## LLM Guidance

This weakness appears when a negative signed value is cast, assigned, or implicitly converted into an unsigned type, most often a function's negative error return (read/receive/format-length calls) flowing into a size, index, or allocation parameter typed as unsigned. Because unsigned types have no sign bit, the conversion silently reinterprets the value as a very large positive number instead of failing, which then bypasses any check that assumes unsigned values are inherently non-negative. The fix is to validate the value against zero while it is still in its signed type, before any conversion, comparison, or arithmetic against an unsigned type occurs.

## Key Principles

- Primary defence: check that a signed value is non-negative before it is converted to, compared with, or stored in an unsigned type.
- Never rely on a post-conversion check (`count > 0`); by then the negative case already wrapped to a large positive value.
- Treat any function whose signature returns a signed type as a signal that a negative value is a meaningful, checkable error case.
- When a signed and an unsigned operand are compared directly, the signed operand is silently converted to unsigned first; validate its sign before the comparison, not by trusting the comparison result.
- Prefer a single consistent type family for a given quantity (all unsigned, or a signed type wide enough to validate safely) instead of converting back and forth.
- Defence-in-depth: enable and enforce compiler warnings for sign conversion so future regressions fail the build rather than passing silently.

## Remediation Steps

- Locate - Find every place a signed value (especially a function's negative-on-error return) is cast, assigned, or compared against an unsigned type such as a size or index type.
- Trace data flow - Follow the signed value from its source (a return value, arithmetic result, or parsed input) to the sink where it crosses into unsigned territory.
- Identify the unsafe pattern - Confirm there is no explicit "value >= 0" check on the signed value before the conversion or mixed-sign comparison.
- Replace with the safe pattern - Add an explicit non-negativity check on the signed value immediately after it is obtained, before any conversion or use as an unsigned quantity, and reject or handle the negative case there.
- Keep types consistent - Where practical, avoid the conversion entirely by keeping the value in one type family for its full lifetime.
- Add secondary controls - Enable compiler warnings/static analysis for sign conversion and sign comparison and treat them as build failures.
- Test - Exercise the conversion path with a negative value, zero, and the type's minimum/maximum boundaries to confirm negative values are rejected before conversion rather than silently accepted as large positive ones.
