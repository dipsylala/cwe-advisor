# CWE-196: Unsigned to Signed Conversion Error

## LLM Guidance

This weakness appears when an unsigned value larger than a signed type's maximum is cast, assigned, or implicitly converted into that signed type, most often a `size_t`-style length or count being assigned into a plain signed integer. The high bit of the unsigned representation becomes the sign bit, so a large legitimate value is silently reinterpreted as negative instead of being rejected, which then defeats bounds checks, loop conditions, or arithmetic that assume the value is non-negative. The fix is to validate the unsigned value against the destination signed type's maximum before the conversion happens, or to avoid the conversion by keeping the value unsigned.

## Key Principles

- Primary defence: compare the unsigned value against the destination signed type's maximum before casting or assigning it.
- Never assign a size/length/count result (string length, container size) directly into a plain signed type without a range check.
- The damage is usually done by a *pair* of conversions: the value goes negative crossing into the signed type, passes an upper-bound-only check written for small positive numbers, then converts straight back at an allocator whose size parameter is unsigned - so a small negative becomes a value near the type's maximum, and the check meant to keep the request small is what let it through. Check the sign as well as the bound.
- A mixed signed/unsigned *comparison* does not produce this direction and belongs to CWE-195; what belongs here is a value somebody has already cast.
- Where the conversion is not actually required, keep the value unsigned for its entire lifetime instead of converting to signed to satisfy convenience or a legacy interface.
- Do not trust "the value is usually small" as a substitute for enforcing the range; the failure only appears once an input crosses the boundary.
- Prefer a single consistent type family for a given quantity (all unsigned, or a validated signed type) rather than converting back and forth.
- Defence-in-depth: enable and enforce compiler warnings for narrowing and sign conversion so future regressions fail the build.

## Remediation Steps

- Locate - Find every place an unsigned value (lengths, sizes, counts) is cast, assigned, or compared against a signed type such as a loop bound, index, or function parameter.
- Trace data flow - Follow the unsigned value from its source (a size-returning call, a count derived from untrusted input) to the sink where it crosses into signed territory.
- Identify the unsafe pattern - Confirm there is no explicit upper-bound check against the signed type's maximum before the conversion.
- Replace with the safe pattern - Add an explicit range check ("value <= SignedType maximum") on the unsigned value before it is cast or assigned, and reject or handle the out-of-range case there.
- Keep types consistent - Where practical, avoid the conversion entirely and keep the value unsigned, or update the receiving interface to accept an unsigned type.
- Add secondary controls - Enable compiler warnings/static analysis for narrowing and sign conversion and treat them as build failures.
- Test - Exercise the conversion path with a value at, and one above, the destination type's maximum, plus the unsigned type's own maximum, to confirm out-of-range values are rejected before conversion rather than silently becoming negative.
