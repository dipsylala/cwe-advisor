# CWE-197: Numeric Truncation Error - C++

## LLM Guidance

C++ inherits C's implicit narrowing in most contexts - `static_cast`, function-style casts, ordinary assignment - so the same silent bit-loss applies to `int64_t` to `int32_t` and `double` to `int`. Brace initialization (`int x{value};`) is the one real improvement: for float-to-integer, it is unconditionally a compile error when the initializer would narrow; for integer-to-integer and integer-to-float, the same source code compiles fine if the value is a constant expression that provably fits, so a brace-init "finding" against a literal or `constexpr` source may not be a narrowing conversion at all. It reports where the conversion is rather than whether the value fits. Everywhere else a validated conversion is still needed, and `static_cast` documents intent without performing any check.

## Key Principles

- Route narrowing conversions through a checked helper built on `std::in_range<Target>(value)` (C++20, `<utility>`), which compares mathematical values and is the only form of the check that survives a change of signedness
- Do not hand-write the guard as `value < numeric_limits<Target>::min() || value > numeric_limits<Target>::max()`: with an unsigned source and a signed target, `min()` converts to the unsigned type first, so the check rejects small valid values and accepts out-of-range ones. It is also exactly what `-Wsign-compare` reports
- Constrain the helper to integral types (`std::integral`) - a floating-point source needs a different check, because `NaN` and infinity must be rejected first and `numeric_limits<int64_t>::max()` is not exactly representable as a `double`
- Use brace initialization for new code so accidental narrowing fails to compile - but `int32_t count{static_cast<int32_t>(length)}` defeats the check rather than satisfying it: the cast makes both sides the same type before the compiler ever evaluates narrowing, so the truncation still happens and now looks reviewed
- Deciding whether a checked conversion throws or returns `bool`/`std::optional` is a codebase-wide choice, not a per-call one - a throwing helper dropped into a `-fno-exceptions` build fails to link or terminates at runtime instead of failing the way the rest of the code expects
- Apply the application's own bound after the type check: a size that fits in `int32_t` can still be an unreasonable allocation
- Keep the wide type to the point of use where possible, so there is no narrowing step to validate
- Build with `-Wconversion -Wfloat-conversion -Wsign-compare` (and `-Werror` in new code), and run tests under `-fsanitize=undefined` - on GCC, also request `float-cast-overflow` explicitly, since GCC excludes it from the default `undefined` umbrella where Clang includes it

## Taint Sinks

`static_cast<int32_t>()` and C-style casts of wider values, `std::make_unique<char[]>(n)`, `resize()`/`reserve()` arguments, array indexing, `int` parameters receiving `int64_t`/`std::size_t`/`std::streamsize`

## Remediation Steps

- Locate - find `static_cast` and assignment narrowings between integer widths, and every float-to-integer conversion
- Trace data flow - determine the widest type the value held and whether any reachable input exceeds the target's range (file sizes, content lengths, and offsets usually can)
- Identify the unsafe pattern - a cast with no range check, or a check written against the already-narrowed value
- Replace with the safe pattern - a `safe_narrow_cast` built on `std::in_range`, throwing on failure
- Bind, encode, validate, or authorize - add the domain limit alongside the type limit and reject rather than clamp
- Harden configuration - enable the conversion warnings, prefer brace initialization, and build tests with `-fsanitize=undefined` (add `float-cast-overflow` explicitly on GCC)
- Test - drive the helper directly with `INT32_MAX + 1`, a value whose low 32 bits are small (`0x100000001`), and for the floating-point form `NaN` and an infinity; assert the conversion is refused rather than performed
