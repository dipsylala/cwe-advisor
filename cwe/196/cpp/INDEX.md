# CWE-196: Unsigned to Signed Conversion Error - C++

## LLM Guidance

C++ inherits C's implicit unsigned-to-signed conversion rules, so `.size()`, `.length()` and any other `std::size_t` value assigned into a signed type wraps once it exceeds that type's maximum - defined as modulo conversion since C++20, implementation-defined before it, and silent either way. What C++ adds is better tooling: `std::numeric_limits` for a portable bound, exceptions so an out-of-range conversion cannot be ignored, and `std::cmp_less`/`std::cmp_greater` (C++20) for comparing mixed-signedness values without converting at all.

## Key Principles

- Prefer not converting: keep the value as `std::size_t` wherever the caller can accept it, and convert once at the boundary that genuinely needs a signed type
- Bound the check with `std::numeric_limits<int>::max()` rather than a hardcoded `INT_MAX`, so it stays correct across platforms with different `int` widths
- Throw (or return `std::optional`) on an out-of-range conversion so it cannot be silently ignored; a wrapped length that reaches the caller is indistinguishable from a real one
- Compare with `std::cmp_greater`/`std::cmp_less` when one operand is signed and the other unsigned - they compare by mathematical value, so no operand is converted before the comparison
- Convert *after* the bounds check, not before: a size narrowed to `int` and then compared is being checked against a value that has already changed
- Container methods returning `size_type` are the usual source; a loop index declared `int` against `.size()` is the same defect in comparison form
- Build with `-Wsign-conversion -Wconversion` (or `/W4` and `C4245`/`C4365` on MSVC) so these conversions become visible

## Taint Sinks

`static_cast<int>(container.size())`, `int` parameters receiving `.size()`/`.length()`, array or container indexing with a converted value, `resize()`/`reserve()` arguments computed from a converted value

## Remediation Steps

- Locate - find casts and assignments from `std::size_t` or another unsigned type into `int`, `short`, or another signed type, including implicit ones at call boundaries
- Trace data flow - determine whether the unsigned value can exceed the signed type's maximum for any reachable input, and what the converted value is subsequently used for
- Identify the unsafe pattern - a narrowing conversion performed before any range check, or a bounds check performed on the already-converted value
- Replace with the safe pattern - a checked helper using `std::numeric_limits`, or a signature change that keeps the value unsigned
- Bind, encode, validate, or authorize - apply the application's own maximum alongside the type's, and reject rather than clamp
- Harden configuration - enable the conversion warnings and build tests with `-fsanitize=undefined` and the standard library's hardened mode
- Test - drive a container past the signed type's maximum where feasible, or unit-test the conversion helper directly with `INT_MAX + 1`, and assert the operation is refused rather than performed on a negative value
