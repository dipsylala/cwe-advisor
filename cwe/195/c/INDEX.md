# CWE-195: Signed to Unsigned Conversion Error - C

## LLM Guidance

C converts a negative signed value to unsigned implicitly - on assignment, on a parameter, or in a comparison with an unsigned operand - with no error and, without `-Wsign-conversion`/`-Wsign-compare`, usually no warning. The two's complement bit pattern is reinterpreted, so any negative number becomes a very large positive one. The usual source is a function whose signed return type exists precisely to carry a negative error code (`read()`, `recv()`, `snprintf()`, any `ssize_t` API) being cast or compared as though it could only be a valid size.

## Key Principles

- Test the error case while the value is still signed: `if (bytes_read < 0) return;` before any cast to `size_t`
- A `> 0` check applied *after* the conversion is not a check - `(size_t)(-1)` is `SIZE_MAX`, which passes it and then becomes an allocation size or a `memcpy` length
- Validate a signed length parameter for `length < 0` before converting it, and only then compare it against the destination's capacity
- Comparing a signed value against an unsigned one converts the signed operand first, so `if (i < buf_size)` with a negative `int i` is true; make both operands the same signedness before comparing
- Use unsigned types for sizes and counts throughout, so no conversion is needed at the point of use, and keep the signed type only where a negative value is meaningful
- Prefer `size_t`/`ssize_t` to `int` for anything derived from a length, and check the result of `snprintf` for a negative return before using it as a length
- Build with `-Wsign-conversion -Wsign-compare -Wconversion` so the implicit conversions become visible, and treat them as errors in new code
- Where the value crosses an API boundary, validate it in the callee too - the caller's check does not travel with the value

## Taint Sinks

`malloc()`/`calloc()` size argument, `memcpy()`/`memmove()` length, `read()`/`recv()` length, array indexing with a converted value, `alloca()`

## Remediation Steps

- Locate - find casts to `size_t`/`unsigned` and comparisons mixing signed and unsigned operands, especially on the return values of `read`, `recv`, `snprintf`, and `ssize_t`-returning functions
- Trace data flow - follow the value from the signed source to the unsigned use, noting where the conversion actually happens (it is often implicit at an assignment or a call)
- Identify the unsafe pattern - a conversion or comparison that happens before the negative case has been excluded
- Replace with the safe pattern - check `< 0` on the signed value first, then convert, then bound-check against the buffer's capacity
- Bind, encode, validate, or authorize - reject a negative length with an error return rather than clamping it to zero, so the caller learns the input was invalid
- Harden configuration - enable `-Wsign-conversion -Wsign-compare` and run tests under `-fsanitize=undefined`
- Test - pass `-1` and `INT_MIN` through every length and count parameter, and simulate `read`/`recv` returning `-1`, asserting that no allocation or copy takes place
