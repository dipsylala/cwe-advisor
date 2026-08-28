# CWE-190: Integer Overflow or Wraparound - Java

## LLM Guidance

Java's `int` and `long` arithmetic wraps silently on overflow - no exception, no warning - the same failure mode as C without the undefined behaviour. The usual consequence is a wrapped value reaching an allocation size, an index calculation, or a security check (a timeout, a rate limit, a quota) rather than memory corruption, since the JVM's bounds-checked arrays turn a negative size into a caught `NegativeArraySizeException`. The logic error is exactly as real. Use `Math.addExact`/`subtractExact`/`multiplyExact`, which throw `ArithmeticException` instead of wrapping.

## Key Principles

- Replace `+`, `-`, `*` with `Math.addExact`, `Math.subtractExact`, `Math.multiplyExact` (Java 8+) on any value derived from input, so an overflow becomes a caught exception rather than a silent result
- Validate the input ranges before the arithmetic as well - bounding `count` and `itemSize` separately stops the problem before it reaches an operator, and gives a clearer error
- `Math.toIntExact(long)` is the right narrowing at a `long`-to-`int` boundary; a plain `(int)` cast truncates silently (CWE-197)
- Watch the mixed-width case: `int * int` is computed in `int` and wraps *before* being assigned to a `long`, so widen an operand first or use `Math.multiplyFull`
- `Math.abs(Integer.MIN_VALUE)` returns `Integer.MIN_VALUE` - still negative - so an `abs()` used to sanitise an index is not a bound
- Use `BigInteger` where the value can legitimately exceed `long` range, and `Math.floorDiv`/`floorMod` where negative operands are possible
- Java has no unsigned primitives before the `Integer.compareUnsigned`/`divideUnsigned` helpers; a value read as a signed `int` from a wire format needs `Integer.toUnsignedLong()` rather than a comparison against zero
- Check the *result* of any counter or accumulator that can be driven by request volume, not only the increment

## Taint Sinks

`new byte[n]`/`new T[n]`, `List.get()`/`subList()` indices, `Math.abs()` used as a bound, arithmetic feeding a timeout, quota, or rate-limit comparison, `(int)` casts of `long`

## Remediation Steps

- Locate - find arithmetic on values derived from request parameters, headers, file metadata, or database columns, particularly multiplications feeding an allocation
- Trace data flow - determine the operand ranges reachable from input and whether the result is used as a size, index, or security threshold
- Identify the unsafe pattern - a plain operator on unbounded operands, a mixed-width multiply, or an `abs()` treated as a bound
- Replace with the safe pattern - `Math.*Exact` for the operation and explicit range validation for the operands
- Bind, encode, validate, or authorize - apply the application's own maximum in addition to the type's, and reject rather than clamp
- Harden configuration - enable static-analysis rules for unchecked integer arithmetic in size and index expressions
- Test - drive each operand with `Integer.MAX_VALUE`, `Integer.MIN_VALUE`, and a pair whose product wraps to zero (`0x40000000 * 4`), and assert an exception rather than a wrapped allocation
