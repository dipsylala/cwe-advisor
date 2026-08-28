# CWE-824: Access of Uninitialized Pointer - C

## LLM Guidance

A pointer with automatic storage that is never explicitly assigned holds an *indeterminate* value - whatever the stack slot last contained. Using it (dereferencing, freeing, or passing it to something that does either) reads or writes through an address the program never chose. Reading an indeterminate value is undefined behaviour rather than merely unspecified, so an optimising compiler may assume the read never happens and reshape the surrounding branch, which is why the same source can fault in a debug build and take a different path in a release build.

## Key Principles

- Declare the pointer at the point of its first assignment, so no window exists in which it is indeterminate - this is the strongest form of the fix
- An early `return` for the failure case is usually what makes that possible: with the precondition rejected up front, the rest of the function runs under one set of assumptions and needs no sentinel
- Where the variable genuinely must exist earlier - a `goto cleanup` epilogue, a value set in one branch and used after - initialize it to `NULL` at the declaration *and* check before dereferencing; the initializer alone converts a wild write into a null dereference but does not remove the bug
- A blanket `= NULL` habit costs something: it silences the compiler's uninitialized-use warning, so a genuinely missing assignment stops being reported and becomes a null-pointer crash at runtime instead of a diagnostic at build time
- An unchecked `fopen`/`malloc` return is a *different* weakness - the pointer there is initialized, just to NULL; that is a missing return-value check, not this
- Give struct pointer fields a defined value at allocation (`calloc`, or an explicit initializer) so a partially built object cannot be freed through a garbage field
- Build with `-Wall -Wextra -Wmaybe-uninitialized` (and `-Werror` in new code) and test under `-fsanitize=memory` or Valgrind, which report the use of the uninitialized value itself rather than only its consequences

## Taint Sinks

Dereference of a pointer not assigned on all paths, `free()` of such a pointer, passing it to `memcpy()`/`strcpy()`, a struct pointer field used after a partial initialization

## Remediation Steps

- Locate - find pointer declarations without an initializer, and check whether every path to their first use assigns them
- Trace data flow - identify branch and `goto` paths (especially error paths and cleanup epilogues) that reach a use without passing through an assignment
- Identify the unsafe pattern - a declaration separated from its assignment by a conditional, or a cleanup label that frees pointers some paths never set
- Replace with the safe pattern - move the declaration to the first assignment and reject the failure case with an early return
- Bind, encode, validate, or authorize - where the variable must be declared early, initialize to `NULL` and guard the dereference and the `free()`
- Harden configuration - enable the uninitialized-use warnings as errors, and use `calloc` or designated initializers for structs containing pointers
- Test - exercise every early-exit and error path, and run under Valgrind or MemorySanitizer to confirm no uninitialized value is used
