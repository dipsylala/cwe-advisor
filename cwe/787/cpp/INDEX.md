# CWE-787: Out-of-bounds Write - C++

## LLM Guidance

C++ inherits C's raw arrays and pointer arithmetic, and `operator[]` on `std::vector` and `std::array` is specified as undefined behaviour out of range rather than as a checked access, so the same writes land outside the allocation. The fix is normally to stop managing size and capacity by hand: let a container own its storage and growth, use `.at()` where the index is not already provably valid, and pass `std::span` instead of a raw pointer plus a separate length.

## Key Principles

- `operator[]` performs no bounds check on any standard container; `.at()` performs it and throws `std::out_of_range`. Reserve `operator[]` for an index already validated or structurally guaranteed, such as a loop bounded by `.size()`
- Let the container grow itself - `buffer.insert(buffer.end(), first, last)` has no size arithmetic, allocation, or copy for calling code to get wrong, unlike a hand-rolled `new[]` plus two `memcpy` calls
- A manual growth path has three independent chances to be wrong (the size addition, the allocation, the copy lengths) and no structural guarantee that they agree; an overflow in `size + extraLen` alone produces an under-allocated buffer the copy then overruns
- Take a `std::span` (C++20) rather than a `(pointer, length)` pair, so the length used for the check is always the length of the data actually pointed at, then check `index >= buffer.size()` before writing
- Handing `.data()` to a C API that writes past `.size()` reintroduces the overflow - the container cannot see writes made through a raw pointer it handed out
- Report a refused write to the caller rather than only logging it; a handler that swallows the exception leaves the caller believing the value was stored
- Where a local `std::array` is the target, the corruption is on the stack and the finding is CWE-121; for `std::vector` or a grown `std::string` the elements are in a separate heap allocation. The missing check is the same either way

## Taint Sinks

`std::vector::operator[]`, `std::array::operator[]`, `new[]` with a computed size, `memcpy()` into `.data()`, raw pointer indexing, `strcpy()`/`sprintf()` on a `char[]`

## Remediation Steps

- Locate - search for `operator[]` writes with a non-constant index, raw `new[]`/`delete[]` buffer management, and C string functions applied to C++ data
- Trace data flow - determine where the index or length originates and whether it is compared against the container's own `.size()` before the write
- Replace the unsafe pattern - convert raw buffers to `std::vector`/`std::string`, unchecked indexing to `.at()`, and hand-rolled growth to `insert()`/`resize()`
- Bind, encode, validate, or authorize - for a non-owning view, take `std::span` and check the index against `buffer.size()` inside the function rather than trusting the caller's length
- Harden configuration - build and test with the standard library's hardened mode: `-D_GLIBCXX_ASSERTIONS` on libstdc++, `-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE` on libc++, and the Microsoft STL's debug container checks (`_ITERATOR_DEBUG_LEVEL` defaults to 2 in debug builds but 0 in release, so set it explicitly if the checks are wanted there), which turn an out-of-range subscript into a deterministic abort
- Test - run under `-fsanitize=address,undefined -g -O1` and Valgrind with normal, boundary, and oversized or negative indices, and assert that `.at()` actually throws for the out-of-range case
