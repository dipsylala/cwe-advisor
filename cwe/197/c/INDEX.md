# CWE-197: Numeric Truncation Error - C

## LLM Guidance

C narrows implicitly whenever a value is assigned or cast to a smaller type - `int64_t` to `int32_t`, `long` to `int`, `double` to `int` - discarding what does not fit, with no runtime check and, without `-Wconversion`, often no warning. Integer narrowing drops the high-order bits, so `0x100000001` becomes `1` in 32 bits; a size computed that way produces a small allocation that a later copy sized from the original value overruns. Floating-point-to-integer narrowing is worse: converting a `double` outside the target type's range is undefined behaviour, not merely a loss of precision.

## Key Principles

- Range-check on the *wide* value before the cast: `value < INT32_MIN || value > INT32_MAX` catches exactly the values whose high bits would be dropped
- Report the failure through an explicit indicator (a `bool` plus an out-parameter) so no call site can proceed on a truncated number
- For floating point, reject `isnan()` and `isinf()` as well as the range, since those conversions are undefined rather than lossy
- Keep the wide type all the way to the sink where possible: a length that stays `int64_t` until it reaches `malloc((size_t)len)` has no narrowing step to check
- Watch for the sizes and the copy diverging - the classic shape is an allocation sized from the truncated value and a copy sized from the original, which is an out-of-bounds write (CWE-787)
- `time_t` narrowed into a 32-bit field is the recurring real-world instance and overflows on 19 January 2038; store and compare it at its native width
- Build with `-Wconversion -Wfloat-conversion` and treat them as errors in new code, and run tests under `-fsanitize=undefined` which reports the invalid float-to-int conversions

## Taint Sinks

`malloc()`/`calloc()` size argument, `memcpy()` length, array indexing, `int` fields receiving `int64_t`/`time_t`/`off_t` values, `(int)` casts of `double`

## Remediation Steps

- Locate - find assignments and casts to a narrower integer type, and every float-to-integer conversion
- Trace data flow - identify the widest type the value ever held and whether any reachable input can exceed the narrow type's range (file sizes, content lengths, timestamps, and offsets usually can)
- Identify the unsafe pattern - a narrowing conversion with no prior range check, or a check written against the already-narrowed value
- Replace with the safe pattern - a checked conversion helper, or a signature change that keeps the wide type to the point of use
- Bind, encode, validate, or authorize - reject an unrepresentable value with an error rather than clamping it, so the caller does not act on a substituted size
- Harden configuration - enable `-Wconversion -Wfloat-conversion`; build tests with `-fsanitize=undefined`
- Test - pass `INT32_MAX + 1`, a value whose low 32 bits are small (`0x100000001`), `NaN`, and an infinity through every conversion, and assert the operation is refused rather than performed at the truncated size
