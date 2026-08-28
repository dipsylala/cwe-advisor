# CWE-196: Unsigned to Signed Conversion Error - C

## LLM Guidance

C converts an unsigned value larger than a signed type's maximum implicitly - on assignment, on a parameter, or by an explicit cast - with no error and, without `-Wsign-conversion`, usually no warning. On mainstream implementations the high bit becomes the sign bit, so `UINT32_MAX` arrives as `-1` in a 32-bit `int`, but the standard leaves an unrepresentable conversion implementation-defined. The remediation therefore does not depend on which value you get: range-check before converting. The usual source is `strlen()` or another `size_t`-returning call assigned straight into an `int`, which works until the input is large enough.

## Key Principles

- Check `value > INT_MAX` while the value is still unsigned, then convert - a check applied after the cast is testing a value that has already wrapped
- Better still, remove the conversion: compare `size_t` against `size_t` and keep lengths and counts unsigned end to end
- Return an explicit error indicator from a conversion helper (a `bool` plus an out-parameter) so every call site has to handle the too-large case rather than silently accepting a wrapped result
- A negative result from a length function is the observable symptom: a subsequent `if (len < 0)` guard may look like a check while the damage - an allocation or index computed from the wrapped value - has already been done elsewhere
- A mixed signed/unsigned *comparison* does not produce this direction: the usual arithmetic conversions convert the unsigned operand to the signed type only when that type can represent all its values, and otherwise convert the signed one. A finding on a mixed comparison belongs to CWE-195; what belongs here is an operand somebody has already cast
- Use fixed-width types (`int32_t`, `uint32_t`) where the range matters, and check the high bit explicitly when narrowing between them
- Build with `-Wsign-conversion -Wconversion` and treat the warnings as errors in new code

## Taint Sinks

`(int)` casts of `size_t`/`strlen()` results, `int` parameters receiving a `size_t` argument, array indexing with a converted value, `malloc()` size computed from a converted value, loop bounds

## Remediation Steps

- Locate - find assignments and casts from `size_t`, `unsigned`, or a fixed-width unsigned type into `int`, `short`, or another signed type
- Trace data flow - determine whether the unsigned value can exceed the signed type's maximum for any reachable input (a length taken from a file, a network frame, or user input usually can)
- Identify the unsafe pattern - a conversion performed before any range check, or a range check written after the cast
- Replace with the safe pattern - a helper that validates `value > INT_MAX` and reports failure, or restructure so no conversion is needed at all
- Bind, encode, validate, or authorize - reject the oversized value with an explicit error rather than clamping it, so the caller does not proceed on a substituted length
- Harden configuration - enable `-Wsign-conversion -Wconversion` and run tests under `-fsanitize=undefined`
- Test - pass a length just above `INT_MAX` (and, for narrower targets, just above `SHRT_MAX`) through every conversion, and assert the operation is refused rather than performed on a negative value
