# CWE-416: Use After Free

## LLM Guidance

A use-after-free occurs when a program continues to access memory or a handle-like reference after the underlying allocation has been released, potentially reading or writing memory that has since been reallocated for an unrelated object - which can corrupt data, crash the process, or be exploited for arbitrary code execution. It commonly arises from a stale pointer left after a free, a resource freed while another component still holds and later dereferences it, or a callback or asynchronous operation that outlives the object it references. The fix is to guarantee no reference to a released allocation is ever dereferenced, primarily by nulling pointers immediately after release and tying an object's lifetime to the code that actually needs it.

## Key Principles

- Set a pointer or reference to null immediately after freeing it, and check for null before any subsequent use
- Ensure an object is not freed while another component still holds a live reference to it; track ownership or use reference counting so release happens only when no reference remains
- Pay particular attention to callbacks, event handlers, and asynchronous operations that may run after the object they reference has already been released
- Prefer ownership and lifetime constructs (smart pointers, reference counting, scope-bound lifetimes) over manually tracked raw pointers passed across components
- Invalidate cached pointers or references when the underlying resource is closed or freed elsewhere, rather than assuming the cache stays in sync

## Remediation Steps

- Locate - Identify the free or release call and every subsequent access to the same pointer or reference
- Trace lifetime and ownership - Determine every component that holds a reference to the object and confirm which one is responsible for releasing it, and when
- Identify the unsafe pattern - Look for a stale pointer used after release, a callback or async task referencing a freed object, or a resource freed while still registered or cached elsewhere
- Replace with the safe pattern - Null the pointer immediately after release and check for null before use, or adopt an ownership construct that defers release until no reference remains
- Synchronize lifetime across components - Ensure any cache, registry, or callback holding a reference is updated or unregistered at the same time the object is freed
- Add secondary controls - Enable memory-safety sanitizers and static analysis in the build and test pipeline to catch regressions
- Test - Exercise code paths where the object is freed and then reused, including concurrent or asynchronous scenarios, under a sanitizer to confirm no access occurs after release
