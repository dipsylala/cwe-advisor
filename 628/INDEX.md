# CWE-628: Function Call with Incorrectly Specified Arguments

## LLM Guidance

Incorrect function arguments (wrong type, wrong order, wrong count, null when required) cause undefined behavior, security check bypass, buffer overflows, null pointer dereferences, and logic errors, often due to API misuse or type confusion. Call functions with correct argument types, order, and count to prevent memory and state corruption.

## Key Principles

- Enforce strict type checking and argument validation at function boundaries
- Use API wrappers or interfaces that prevent argument misuse
- Validate argument order for functions with multiple same-type parameters
- Reject null arguments for security-critical functions unless explicitly allowed
- Apply compiler warnings and static analysis to catch mismatches early
- Give same-typed arguments different types so a transposition stops compiling: a `std::span` carries pointer and length as one value, and a `Length`/`Bytes` wrapper or an enum instead of a bare `int` is the C++ equivalent of naming the parameter - in C, a small struct passed by value does the same job
- Make the compiler's format checking fatal (`-Wformat=2`, `-Werror=format-security`) and annotate your own printf-like wrappers with `__attribute__((format(printf, m, n)))`; without the attribute the compiler cannot tell which parameter is the format string and the wrapper becomes a hole in the checking
- Turn on the analyzer rules for the known transpositions - the swapped-`memset` case has a dedicated warning (`-Wmemset-transposed-args`) - rather than relying on review to spot a call that compiles cleanly

## Remediation Steps

- Locate vulnerable calls - Search for functions with multiple same-type parameters, buffer operations (memcpy, strncpy), and authentication/authorization functions
- Verify argument order - Check dest/src positioning, user/password order, and size/length parameter placement
- Add type safety - Use strongly-typed wrappers, enums instead of integers, and null-safe types
- Validate inputs - Check for null, verify types match expectations, and ensure counts align with buffer sizes
- Enable compile-time checks - Turn on strict compiler warnings, use static analyzers, and apply linting rules for function calls
- Test edge cases - Verify behavior with null, wrong types, swapped arguments, and boundary values
