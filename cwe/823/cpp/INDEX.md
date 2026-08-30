# CWE-823: Use of Out-of-range Pointer Offset - C++

## LLM Guidance

C++ inherits C's raw pointer arithmetic and array indexing, so the same unchecked-offset problem applies wherever code uses `new[]`, raw pointers, or `operator[]`. The fix is largely structural: replace manual arithmetic with containers and views that carry their own bounds, so the size travels with the data rather than in a second variable that can go stale.

## Key Principles

- Use `std::vector`, `std::array`, or `std::span` instead of raw pointers and `new[]`/`delete[]`
- `.at()` checks the index against the container's actual size on every call and throws `std::out_of_range`; use it wherever an out-of-range index is a condition to handle rather than an impossibility
- `std::span::operator[]` is unchecked and `std::span` has no `.at()` before C++26, so a span's callee writes the check itself - `if (index >= s.size()) throw ...`
- Do not add a manual bounds check in front of `.at()` "just in case" - it already validates and throws, and a redundant guard ahead of it is dead code with nothing to stay in sync with. The inverse mistake is deleting a check because "the container handles it" when the container is a `span`, which validates nothing
- Prefer range-based iteration where the body does not need the index: no offset is computed, so none can be wrong
- Validate the offset as an integer before forming a pointer - a pointer more than one past the end is already undefined behaviour, so a comparison on the formed pointer can be optimised away
- Take `(pointer, size)` as a `std::span` rather than two parameters, so the length used for the check is the length of the data actually passed
- An iterator or pointer taken before a `resize()`, `push_back()`, or `erase()` is invalid afterwards - re-acquire it rather than reusing it
- Build tests with `-fsanitize=address,undefined` and the standard library's hardened mode (`-D_GLIBCXX_ASSERTIONS`, `-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST` - its `valid-element-access` check already covers `operator[]`; `extensive` adds checks unrelated to element access), which check `operator[]` too - AddressSanitizer alone often misses a `std::vector` off-by-one, since an index one past the end frequently still lands inside capacity the vector already reserved; the hardened-mode check is what catches that specific case

## Taint Sinks

`operator[]` with a computed index, `std::span::operator[]`, raw pointer arithmetic over a `new[]` buffer, `.data() + offset`, `std::memcpy()` with a computed destination

## Remediation Steps

- Locate - find raw `new[]`/pointer arithmetic, `operator[]` calls with a non-constant index, and functions taking a pointer plus a separate length
- Trace data flow - identify where the index or offset originates and whether it is compared against the container's own `.size()`
- Identify the unsafe pattern - an index used before validation, a loop bounded with `<=`, or a length parameter trusted independently of the buffer
- Replace with the safe pattern - convert the buffer to a container, the index access to `.at()`, and the `(pointer, length)` parameter pair to `std::span`
- Bind, encode, validate, or authorize - inside a function taking a `std::span`, check the index against `s.size()` explicitly, since the span does not
- Harden configuration - enable the hardened standard library mode in test builds so `operator[]` aborts deterministically out of range
- Test - exercise indices of `0`, `size - 1`, `size`, and a very large value, and confirm `.at()` throws and the span check rejects rather than reading adjacent memory
