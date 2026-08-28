# CWE-416: Use After Free

## LLM Guidance

A use-after-free occurs when a program continues to access memory or a handle-like reference after the underlying allocation has been released, potentially reading or writing memory that has since been reallocated for an unrelated object - which can corrupt data, crash the process, or be exploited for arbitrary code execution. It commonly arises from a stale pointer left after a free, a resource freed while another component still holds and later dereferences it, or a callback or asynchronous operation that outlives the object it references. The fix is to guarantee no reference to a released allocation is ever dereferenced, primarily by giving each allocation a single owner whose lifetime bounds every use of it. Nulling the pointer after release is a secondary measure - it turns a stray later use into an immediate fault, but it reaches only the one variable that was nulled.

## Key Principles

- Give each allocation one owner and make release that owner's responsibility alone; every other reference either borrows for a strictly shorter period or shares in the ownership
- Ensure an object is not freed while another component still holds a live reference; reference counting makes release happen only when none remains
- Pay particular attention to callbacks, event handlers, and asynchronous operations that may run after the object they reference has already been released
- Invalidate cached pointers or references when the underlying resource is closed or freed elsewhere, rather than assuming the cache stays in sync
- Freeing does not make memory inaccessible: the allocator returns the block to its free list while the pages stay mapped, so the write succeeds with no fault and no symptom at the line that holds the defect
- Null the pointer at the point of release and check for null before use, but treat that as the secondary control: there is no way to find every alias, and the pointer that gets used is usually not the one that was nulled. MITRE's own note records that its usefulness falls away as the data structure grows
- Make every reference an owner where the language allows it, so release is whatever happens last and no enumeration of aliases is required
- Use a weak reference for an alias that must not extend the lifetime, and note why `upgrade()`/`lock()` beats a null check: it answers the liveness question *by producing an owner*, so the object cannot be released between the check and the use
- Where the access happens because a signal handler ran concurrently, the root cause is CWE-364

## Remediation Steps

- Locate - Identify the free or release call and every subsequent access to the same pointer or reference
- Trace lifetime and ownership - Determine every component that holds a reference to the object and confirm which one is responsible for releasing it, and when
- Identify the unsafe pattern - Look for a stale pointer used after release, a callback or async task referencing a freed object, or a resource freed while still registered or cached elsewhere
- Replace with the safe pattern - Adopt an ownership construct that defers release until no reference remains, then null the owner's pointer at the point of release so any alias you missed faults instead of silently reading reused memory
- Synchronize lifetime across components - Ensure any cache, registry, or callback holding a reference is updated or unregistered at the same time the object is freed
- Add secondary controls - Enable memory-safety sanitizers and static analysis in the build and test pipeline to catch regressions
- Test - Exercise code paths where the object is freed and then reused, including concurrent or asynchronous scenarios, under a sanitizer to confirm no access occurs after release
