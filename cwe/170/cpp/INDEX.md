# CWE-170: Improper Null Termination - C++

## LLM Guidance

`std::string` tracks its own length and always terminates internally, so most of this weakness disappears once code is fully converted to it - `.c_str()` returns a terminated buffer whatever the content. It reappears at the boundaries where C++ still touches raw memory: a `std::vector<char>` or `char*` filled by a C API (`recv()`, a legacy library call) carries no terminator guarantee, and older code that builds C-style buffers by hand carries the C rules unchanged.

## Key Principles

- `std::vector<char>::data()` is a pointer to storage with no terminator - passing it to `printf("%s", ...)` or any C string function after a `recv()` that filled the whole vector reads past the allocation
- Build a `std::string` from a pointer *and an explicit length* (`std::string(buffer.data(), bytes_read)`) rather than from a presumed-terminated `char*`; that removes the termination question instead of trying to satisfy it
- Convert an incoming `const char*` to `std::string` once, at the interop boundary, so only that single conversion depends on the C side's contract
- Keep `.c_str()` at the point of the C call, as late and as narrow as possible, rather than managing a raw buffer through the whole function
- `strncpy` behaves identically in C++: filling a fixed-size `char[]` from a `std::string` needs the same reserved final byte and explicit terminator
- Guard a read with `bytes_read < 0` for the error case and handle `0` (peer closed) as an empty result - a `> 0` guard skips the terminator on exactly the closed-connection path
- Prefer `std::string_view` for passing text you do not own, but remember it is *not* guaranteed terminated - never hand `.data()` from a view to a C string function
- `std::string::data()` only gained `c_str()`'s termination guarantee in C++11; on a codebase that still targets an older standard, or that writes through a non-`const` pointer obtained from `data()`, the guarantee does not hold

## Taint Sinks

`std::vector<char>::data()` passed to a C string function, `std::string_view::data()`, `strncpy()` into a `char[]`, `recv()`/`read()` into `.data()`, `memcpy()` into a buffer later read as a string

## Remediation Steps

- Locate - find raw `char[]`/`std::vector<char>` buffers filled by C APIs, and every place `.data()` or a raw pointer is passed to something that scans for a terminator
- Trace data flow - follow the buffer from the fill to each use as a string, including error and zero-byte paths
- Identify the unsafe pattern - a C API filling the entire buffer with no byte reserved, or a `std::string_view`/`vector` pointer handed to a C string function
- Replace with the safe pattern - construct a `std::string` from the pointer and the byte count returned by the read, and return that instead of the raw buffer
- Bind, encode, validate, or authorize - where the source may exceed a fixed legacy buffer, reject rather than silently truncate, so the caller does not act on a different value
- Harden configuration - build tests with `-fsanitize=address` and the standard library's hardened mode so an over-read aborts deterministically
- Test - exercise a read that fills the buffer exactly, a zero-byte read from a closed peer, and a read error; confirm under ASan that nothing reads past the storage
