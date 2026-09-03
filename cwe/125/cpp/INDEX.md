# CWE-125: Out-of-bounds Read - C++

## LLM Guidance

C++ inherits C's raw arrays and pointer arithmetic, and `operator[]` on `std::vector`, `std::array` and `std::string` performs no bounds check, so an attacker-influenced index reads whatever memory follows the container's buffer. The fix is normally to stop indexing by hand: use the bounds-checked `.at()`, prefer range-based iteration that computes no index at all, and pass `std::span` (C++20) so a pointer and its length cannot drift apart.

## Key Principles

- `operator[]` is undefined behaviour out of range on every standard container - the safety comes from `.at()` or iterators, not from having stopped using a raw array
- Use `.at()` wherever the index is not already validated or structurally guaranteed; keep `operator[]` for a loop bounded by `.size()`
- Apply the fix at every access point: switching the accessor the finding named while a nearby helper or an internal loop still uses `operator[]` on the same container leaves the read open
- Take a `std::span<const T>` rather than a `(pointer, length)` pair, and validate the requested length against `buffer.size()` - the span's size is the size of the data actually passed, unlike a second parameter that can disagree with it
- Check the length before subtracting it. `offset > buffer.size() - length` is unsigned arithmetic: when `length` exceeds `buffer.size()` the subtraction wraps to a huge value and the guard never fires - for exactly the oversized-length input the finding is about. Test `length > buffer.size() || offset > buffer.size() - length`, in that order, so the subtraction only runs once it cannot wrap. `offset + length <= buffer.size()` has the mirror problem: the addition wraps for a large `offset`
- `std::span` gained `.at()` only in C++26, so on C++20/23 `span[i]` is an unchecked read like any raw index: compare against `.size()` explicitly. `.subspan()` is not a safe alternative - the standard states its offset and count as *preconditions*, not as checks, with no throws clause, so exceeding them is undefined behaviour exactly like an out-of-range subscript
- Validate against the container's current `.size()`, not a separately tracked size variable, which can be stale after a resize, move, or reallocation
- Prefer a range-based `for` where the loop body does not need the index: there is no boundary calculation left to get wrong
- `.at()` throwing is only useful if the caller learns about it - return a status or let the exception propagate rather than logging and continuing with a placeholder

## Taint Sinks

`std::vector::operator[]`, `std::array::operator[]`, `std::string::operator[]`, raw pointer indexing and pointer arithmetic, `memcpy()` from `.data()` with an unvalidated length

## Remediation Steps

- Locate - search for `operator[]` reads with a non-constant index, functions taking a raw pointer plus a separate length, and manual index loops
- Trace data flow - identify where the index or length originates (request, file, network frame, prior calculation) and whether it is ever compared with the container's own size
- Identify the unsafe pattern - a read whose index is not checked against `.size()`, or a length parameter trusted independently of the buffer it accompanies
- Replace with the safe pattern - `.at()` for individual accesses, `std::span` for views, range-based iteration where no index is needed
- Bind, encode, validate, or authorize - check `requestedLength > buffer.size()` inside the function rather than trusting the caller, and only then `offset > buffer.size() - requestedLength`; neither `offset + length` nor `size() - length` is safe on its own in unsigned arithmetic
- Harden configuration - build tests with `-D_GLIBCXX_ASSERTIONS` (libstdc++, already enabled at `-O0`), `-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST` (libc++ 18 and later; LLVM 17 spelled this `_LIBCPP_ENABLE_HARDENED_MODE`, and a name the toolchain does not recognise is silently inert), or the Microsoft STL's debug container checks. libc++ traps on a failed check; its `fast` mode already covers element access, so `extensive` is not what buys the bounds check
- Test - run under `-fsanitize=address,undefined -g -O1` and Valgrind with normal, boundary, and oversized or negative indices
