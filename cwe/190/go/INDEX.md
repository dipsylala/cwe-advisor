# CWE-190: Integer Overflow or Wraparound - Go

## LLM Guidance

Go has no checked arithmetic and no overflow exception: signed and unsigned integer overflow both
wrap silently and are defined behaviour, so a length or index computed from request data can wrap
past its own validation without any runtime signal. `int` and `uint` are platform-width - 64-bit on
amd64 and arm64, 32-bit on 386 and arm - so the same expression overflows on one build target and
not another. The fix is an explicit precondition test before the arithmetic, sized to the actual
type, plus an application limit on the result.

## Key Principles

- Check before the operation, not after: because wrapping is defined rather than undefined, a
  post-hoc test like `if a+b < a` does work for the wrap it catches, but it is easy to get wrong for
  mixed signs and it does nothing for multiplication - prefer `count > math.MaxInt/size` before a
  multiply
- Use the `math` constants rather than literals so the check follows the platform: `math.MaxInt`,
  `math.MinInt` and `math.MaxUint` (all added in Go 1.17), or `math.MaxInt32` where a fixed width is
  genuinely what is meant. Hard-coding `2147483647` silently
  becomes the wrong bound on a 64-bit build, and the right one for the wrong reason on 32-bit
- `int` is not a fixed width. A value that fits `int` on the developer's amd64 machine can overflow
  the same code compiled for a 32-bit target, so size the check to the type the value will actually
  occupy - and note `len()`, `cap()` and `strconv.Atoi` all return `int`
- Conversions truncate silently and are a distinct sink from arithmetic: `int32(someInt64)` discards
  the high bits with no panic. Parse to the width you want with `strconv.ParseInt(s, 10, 32)`, which
  returns an error on out-of-range input, rather than parsing wide and narrowing afterwards
- Unsigned wraparound is the dangerous case for lengths: `uint(0) - 1` is a very large number, so a
  subtraction on a `uint` length or offset must be guarded with a comparison before it runs, not by
  testing the result for negativity - it cannot be negative
- Bound the request before the arithmetic where the operand is a body or header size:
  `http.MaxBytesReader` caps what can arrive, which removes whole ranges of operand from
  consideration
- A slice expression is a sink as much as an index is: `b[i:j]` panics on an out-of-range result,
  which turns a wrapped calculation into a denial of service rather than memory corruption - still a
  finding, and still fixed by bounding the operands
- Apply the application's own maximum in addition to the type's, and reject rather than clamp

## Taint Sinks

`make([]T, n)`, `make(map[K]V, n)`, slice indexing and slice expressions `b[i:j]`, `copy()` lengths,
`int32()`/`int()`/`uint()` conversions of wider values, `strconv.Atoi` results used as a size,
arithmetic feeding a timeout, quota, or rate-limit comparison

## Remediation Steps

- Locate - find arithmetic on values from `r.FormValue`, a decoded JSON field, a header, or file
  metadata, particularly multiplications and additions feeding `make`, a slice expression, or `copy`
- Trace data flow - establish the operand ranges reachable from input and the width of the type the
  result lands in, including any conversion on the way
- Identify the unsafe pattern - a plain operator on unbounded operands, a narrowing conversion, or a
  subtraction on an unsigned length
- Replace the unsafe pattern - add the precondition test before the operation (`count > math.MaxInt/size`
  for a multiply, `a > math.MaxInt-b` for an add, `offset > length` before an unsigned subtraction)
  and return an error rather than continuing
- Bind, encode, validate, or authorize - parse at the intended width with `strconv.ParseInt` and its
  `bitSize` argument, and apply the application's own maximum to the result
- Harden configuration - wrap request bodies in `http.MaxBytesReader` before decoding, and build with
  `GOARCH` set to every target that ships so a 32-bit assumption is exercised
- Test - drive each operand with `math.MaxInt`, `math.MinInt` and a pair whose product wraps to a
  small positive value, and assert an error return rather than a wrapped `make` or a panic
