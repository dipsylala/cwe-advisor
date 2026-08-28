# CWE-190: Integer Overflow or Wraparound - C#

## LLM Guidance

C# integral arithmetic is **unchecked by default**: `int.MaxValue + 1` silently becomes
`int.MinValue` rather than throwing, so a size, index, or limit computed from request data can wrap
past the validation that was meant to bound it. The default is set by the `CheckForOverflowUnderflow`
compiler option, which is unset unless the project turns it on. The fix is to make the specific
calculation throw - a `checked` expression or block, or `Math`/`decimal` operations that signal
rather than wrap - and to bound the operands independently of the type's own limits.

## Key Principles

- Wrap the calculation in `checked(...)` or a `checked { }` block so an overflow raises
  `OverflowException` instead of producing a wrapped value that downstream code trusts
- `checked` and `unchecked` apply only to what is **textually** inside them - calling a method from
  inside a `checked` block does not make that method's arithmetic checked. Put the keyword around the
  operation itself, not around the call site that leads to it
- Turning on `<CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>` in the project file
  changes the default for the whole assembly. It is a real hardening step, but it changes behaviour
  everywhere at once: code that relied on wrapping (hash mixing, checksum accumulation, deliberate
  two's-complement tricks) starts throwing, so it is a separate change from fixing the reported line
- Constant expressions are the exception: they are checked by default and overflow is a compile-time
  error, so a literal calculation that compiles proves nothing about the runtime path beside it
- Explicit numeric conversions are governed by the same context - `(int)someLong` truncates silently
  in an unchecked context. `checked((int)value)` throws, and `Convert.ToInt32(value)` throws
  regardless of context, which is why it is the safer narrowing when the value is attacker-influenced
- `decimal` throws on overflow in both contexts, and a `decimal`-to-integral conversion that is out of
  range always throws, so neither depends on the compiler option
- `float`, `double` and `Half` saturate to `PositiveInfinity`/`NegativeInfinity` rather than wrapping,
  so overflow there is detectable with `double.IsInfinity` even in an unchecked context - but
  converting an infinite or NaN double to an integral type in an unchecked context yields an
  unspecified value rather than an error
- A user-defined checked operator may not throw even inside a `checked` block, so a custom numeric
  type gives no guarantee without reading its operator implementations
- Apply the application's own maximum in addition to the type's, and reject rather than clamp - a
  value that does not overflow can still be an unreasonable allocation

## Taint Sinks

`new byte[n]`/`new T[n]`, `Array.Resize`, `Marshal.AllocHGlobal`, `MemoryStream` capacity, `List<T>`
capacity, `(int)`/`(uint)` casts of wider types, `checked`-less arithmetic feeding `Take`/`Skip`, a
quota, a timeout, or a rate-limit comparison

## Remediation Steps

- Locate - find arithmetic on values from `HttpRequest`, a deserialized model, file metadata, or a
  database column, particularly multiplications and additions that size an allocation or an index
- Trace data flow - establish the operand ranges reachable from input, and whether the result becomes
  a size, an index, or a security threshold
- Identify the unsafe pattern - plain operators on unbounded operands, a narrowing cast without
  `checked`, or a `checked` block that wraps the call rather than the arithmetic
- Replace the unsafe pattern - put the operation inside `checked(...)`, or use `Convert.ToInt32` where
  the fix is a narrowing conversion, and catch `OverflowException` into a request rejection rather
  than letting it surface as a 500
- Bind, encode, validate, or authorize - bound each operand and the result against the application's
  own limit before the value reaches the allocation or index
- Harden configuration - consider `<CheckForOverflowUnderflow>` for the assembly as a follow-up, after
  checking the codebase for arithmetic that wraps deliberately
- Test - drive each operand with `int.MaxValue`, `int.MinValue`, and a pair whose product wraps to a
  small positive value, and assert a rejected request rather than a wrapped allocation
