# CWE-121: Stack-based Buffer Overflow - C++

## LLM Guidance

C++ inherits C's raw arrays and C string functions, so a local `char buffer[64]`, or a local `std::array` indexed with unchecked `operator[]`, carries exactly the same risk. The difference is that C++ offers types that manage their own size or check bounds on request, so the fix is normally to stop using fixed-size stack buffers and manual indexing for anything whose size depends on input, rather than to hand-write a more careful bounds check.

## Key Principles

- Which container puts the write on the stack decides the CWE: `std::array` stores its elements inline, so overflowing a local one is CWE-121, while `std::vector` and a grown `std::string` keep their elements in a separate heap allocation and an out-of-range write there is CWE-787 (heap variant CWE-122). The missing check and the fix are identical; what differs is what gets corrupted
- Use `std::string` for text and `std::vector`/`std::array` for other data instead of a raw stack array sized at compile time
- `operator[]` is unchecked undefined behaviour on every standard container including `std::array` and `std::vector`; use `.at()` wherever the index is not already provably in range, and reserve `operator[]` for a loop bounded by `.size()`
- Switching from a C array to a C++ container adds no bounds checking on its own - the safety comes from `.at()` or an explicit index check
- Where a genuine upper bound exists, reject the oversized value rather than calling `resize()`: truncation substitutes a different value, so an over-long username silently becomes a valid-looking one belonging to somebody else, and a UTF-8 value can be cut mid-sequence
- Report the failure when a checked access is refused - a `void` handler that logs and returns leaves the caller believing the write happened, trading a memory-safety bug for silent data loss
- Wrapping `operator[]` in `try`/`catch` catches nothing: it does not throw, and the undefined behaviour has already happened before any exception machinery could run
- Passing `.data()` to a C API that writes back past `.size()` reintroduces the overflow - the container cannot see writes made through a raw pointer it handed out

## Taint Sinks

`strcpy()`, `strcat()`, `sprintf()` on a `char[]`, `std::array::operator[]`, `std::vector::operator[]`, `memcpy()` into `.data()`

## Remediation Steps

- Locate - search for fixed-size `char` arrays, C string functions, and `operator[]` writes whose index comes from input
- Trace data flow - determine whether the index or length is bounded by the container's own `.size()` anywhere before the write, and whether the container's storage is inline (stack) or heap
- Replace the unsafe pattern - convert the buffer to `std::string`/`std::vector`, and convert unchecked indexing to `.at()`
- Bind, encode, validate, or authorize - enforce any real length limit by rejecting with `std::length_error` rather than resizing
- Harden configuration - build tests with `-fsanitize=address,undefined -g -O1`, and enable `_GLIBCXX_ASSERTIONS` (libstdc++) or the equivalent hardened mode so normally-unchecked operations are checked in test builds
- Test - assert that `.at()` actually throws and is handled for an out-of-range index, and exercise normal, boundary, and oversized/negative indices under the sanitizers
