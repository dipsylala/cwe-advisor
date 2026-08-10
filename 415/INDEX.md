# CWE-415: Double Free

## LLM Guidance

A double free occurs when memory that has already been deallocated is deallocated a second time, corrupting the memory allocator's internal bookkeeping in a way that can crash the process or be leveraged for code execution. It typically arises from unclear pointer ownership (multiple owners each freeing the same allocation), a pointer freed on both a normal path and an error-handling or cleanup path, or a missing check before a repeated release. The fix is to establish single, unambiguous ownership for every allocation and make it structurally impossible to release the same allocation twice.

## Key Principles

- Establish exactly one clear owner responsible for releasing each allocation; do not let multiple code paths independently free the same pointer
- Set a pointer to null immediately after it is freed, and treat freeing a null pointer as a safe no-op
- Prefer ownership-tracking constructs that free automatically and exactly once over manual free calls scattered across normal and error paths
- Audit error-handling and cleanup paths specifically; double frees frequently occur when both the normal path and a cleanup path release the same resource
- Never free a resource inside a callback, destructor, or shared structure without confirming no other owner will also free it

## Remediation Steps

- Locate - Identify every call site that releases the pointer or allocation flagged by the finding
- Trace ownership - Determine which code path is the true, single owner responsible for release, and identify any other path that also releases it
- Identify the unsafe pattern - Look for the same pointer freed on both a normal and an error or cleanup path, freed in a loop, or freed by more than one owner of a shared structure
- Replace with the safe pattern - Consolidate release to a single, unambiguous point, or adopt an ownership-tracking construct that releases automatically and exactly once
- Null out freed pointers - Set freed pointers to null immediately so any accidental repeat release becomes a safe no-op rather than a double free
- Add secondary controls - Enable memory-safety sanitizers and static analysis in the build and test pipeline to catch regressions
- Test - Exercise all normal and error paths, including early returns, under a sanitizer to confirm no allocation is released more than once
