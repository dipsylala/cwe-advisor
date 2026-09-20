# CWE-415: Double Free

## LLM Guidance

Usually unclear ownership - several owners each freeing the same allocation - or a pointer released on both a normal path and an error or cleanup path. Where the second free happens because a signal interrupted a function mid-deallocation, the root cause is CWE-364 and the signal handling is what to fix first.

## Key Principles

- Establish exactly one clear owner responsible for releasing each allocation; do not let multiple code paths independently free the same pointer
- Set a pointer to null immediately after it is freed, and treat freeing a null pointer as a safe no-op
- Prefer ownership-tracking constructs that free automatically and exactly once over manual free calls scattered across normal and error paths
- Audit error-handling and cleanup paths specifically; double frees frequently occur when both the normal path and a cleanup path release the same resource
- Never free a resource inside a callback, destructor, or shared structure without confirming no other owner will also free it
- `free` receives the address, not the variable, so it cannot change the caller's pointer: after the first call the variable still holds a value indistinguishable from a valid pointer, and nothing about the second call looks wrong where it is written
- Single ownership makes the question unaskable rather than answered correctly - with no release call on any path out of the function, no path can contain a second one
- Nulling at release reaches only the variable passed in; a caller's local, a struct field, or a node still linked into a list is untouched, which is why it is the mitigation and ownership is the fix

## Remediation Steps

- Locate - Identify every call site that releases the pointer or allocation flagged by the finding
- Trace ownership - Determine which code path is the true, single owner responsible for release, and identify any other path that also releases it
- Identify the unsafe pattern - Look for the same pointer freed on both a normal and an error or cleanup path, freed in a loop, or freed by more than one owner of a shared structure
- Replace with the safe pattern - Consolidate release to a single, unambiguous point, or adopt an ownership-tracking construct that releases automatically and exactly once
- Null out freed pointers - Set freed pointers to null immediately so any accidental repeat release becomes a safe no-op rather than a double free
- Add secondary controls - Enable memory-safety sanitizers and static analysis in the build and test pipeline to catch regressions
- Test - Exercise all normal and error paths, including early returns, under a sanitizer to confirm no allocation is released more than once
