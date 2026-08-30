# CWE-195: Signed to Unsigned Conversion Error - C++

## LLM Guidance

C++ inherits C's conversion rules, so a negative `int` assigned to a `std::size_t` becomes a very large positive value with no diagnostic. What C++ adds is a standard library that expresses nearly every length and index as `std::size_t` - `.size()`, `operator[]`, `resize()`, `reserve()`, `std::span::subspan` - so any signed arithmetic that produces a length or offset has to cross into unsigned territory before it can be used, and that crossing is where the defect lives.

## Key Principles

- Convert through a checked helper that rejects both a negative value and one too large for the target type, rather than casting at the call site
- Write the range check with `std::cmp_less`/`std::cmp_greater` (C++20), which compare by mathematical value - a plain `value > std::numeric_limits<Unsigned>::max()` converts `value` to unsigned first and lets `-1` through, so the guard falls to the bug it is checking for
- Before C++20, write it as `value < 0 || static_cast<std::uintmax_t>(value) > MAX`, in that order: the sign test must come first
- Have the helper return `std::optional` (or use `gsl::narrow`, which throws `gsl::narrowing_error`, where the project already depends on GSL) so the policy stays at the call site, which knows whether an out-of-range value is a client error or a bug
- Apply an application-level upper bound as well as the type's: a value that converts cleanly can still request an allocation large enough to be a denial of service
- Prefer `std::ssize()` and signed indices in loop arithmetic so no conversion is needed until the container is actually indexed, and convert once at that point - `for (size_t i = data.size() - 1; i >= 0; --i)` has two independent bugs with an unsigned `i`: `size() - 1` wraps to `SIZE_MAX` when the container is empty, and `i >= 0` is a tautology that never terminates
- Checking `count <= src.size()` is not enough once a start offset is involved: `first=4090, count=10` against a 4096-byte source passes that check but still reads 4 bytes past the end. Check `first <= src.size()` first, then `count > src.size() - first` - not `first + count > src.size()`, which can itself wrap
- A `static_cast` added only to silence `-Wsign-compare`/`-Wsign-conversion` makes the warning disappear without changing what the code does - confirm the value is actually validated, not just uniformly typed
- Enable `-Wsign-conversion -Wsign-compare -Wconversion`; the conversions here are implicit and invisible without them
- The C entry covers the same conversion at the syscall boundary (error returns from `read()` and friends); this one covers container and iterator idioms

## Taint Sinks

`std::vector::resize()`/`reserve()`, `operator[]` with a converted index, `std::span::subspan()`, `std::string::substr()`, `new T[n]`, `memcpy()` length

## Remediation Steps

- Locate - find signed variables (`int`, `long`, a difference of two iterators, a parsed value) that reach a container size, index, or length parameter
- Trace data flow - identify where the conversion happens; it is usually implicit at the call rather than an explicit cast
- Identify the unsafe pattern - a conversion or a mixed comparison that occurs before the negative case has been excluded
- Replace with the safe pattern - route the value through a checked `to_unsigned` helper (or `gsl::narrow`) and act on its failure
- Bind, encode, validate, or authorize - add the application's own maximum alongside the type's, and reject rather than clamp
- Harden configuration - build tests with `-fsanitize=undefined` and the standard library's hardened mode so an out-of-range index aborts deterministically
- Test - pass `-1`, `INT_MIN`, and a value just above the target type's maximum through every length and index parameter, and assert the operation is refused rather than performed at a wrapped size
