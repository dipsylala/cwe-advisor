# CWE-197: Numeric Truncation Error - Java

## LLM Guidance

Java's narrowing primitive conversions are silent: the compiler requires an explicit cast, and the cast itself performs no range check. A `long` outside `int`'s range loses its high-order bits when cast, which can produce an unrelated - sometimes negative - value. A `double`-to-`int` cast is defined rather than undefined here, but "defined" means it clamps to `Integer.MAX_VALUE`/`MIN_VALUE` and yields `0` for `NaN`, so out-of-range input still produces a value the caller did not expect. `float` and `double` also lose precision on ordinary arithmetic, which matters wherever money is involved.

## Key Principles

- Use `Math.toIntExact(long)`, which performs the range check and throws `ArithmeticException` on overflow, in preference to a hand-written cast
- Where a helper is written by hand, check `value < Integer.MIN_VALUE || value > Integer.MAX_VALUE` on the `long` before casting and throw rather than return a substituted value
- For floating point, reject `Double.isNaN()` and `Double.isInfinite()` explicitly before the range check - the cast's clamp-and-continue behaviour hides both
- Apply the domain's own limit as well as the type's: a size that fits in `int` can still be an unreasonable allocation, and `new byte[]` with a negative length throws while a truncated *positive* length silently under-allocates
- Use `Math.addExact`/`multiplyExact`/`subtractExact` for arithmetic that must not wrap, so an overflow surfaces as an `ArithmeticException` instead of a wrapped value
- Use `BigDecimal` (with an explicit `RoundingMode`) for monetary calculations rather than `double`, and never construct it from a `double` literal
- Watch for the truncation happening at an API boundary - `long` file sizes, `System.currentTimeMillis()`, `InputStream.transferTo()` counts, and JDBC `getLong` results are the common wide sources

## Taint Sinks

`(int)` casts of `long`/`double`, `new byte[n]`, `List.get(index)`, `Math.toIntExact()` callers ignoring the exception, `int` fields assigned from `long` columns or headers

## Remediation Steps

- Locate - find explicit narrowing casts (`(int)`, `(short)`, `(float)`) and `int` fields or parameters receiving `long`/`double` values
- Trace data flow - identify the widest type the value held and whether a reachable input can exceed the target's range
- Identify the unsafe pattern - a cast with no prior range check, or a check performed on the already-narrowed value
- Replace with the safe pattern - `Math.toIntExact()` or a validating helper that throws `IllegalArgumentException`
- Bind, encode, validate, or authorize - add the application's own upper bound and reject rather than clamp
- Harden configuration - enable compiler linting for lossy conversions and use `Math.*Exact` arithmetic on values derived from input
- Test - pass `Integer.MAX_VALUE + 1L`, a `long` whose low 32 bits are small, `Double.NaN`, and `Double.POSITIVE_INFINITY` through every conversion and assert an exception rather than a truncated result
