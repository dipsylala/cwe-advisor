# CWE-401: Missing Release of Memory after Effective Lifetime (Memory Leak)

## LLM Guidance

A memory leak occurs when an allocation, or an object retaining memory (a growing cache, an unclosed handle-bearing object, a lingering reference), is never released once it is no longer needed, causing memory use to grow over the application's lifetime until performance degrades or the process crashes - a denial-of-service risk. It commonly comes from unintended lingering references rather than a literal missing free: garbage collection only reclaims what is unreachable, so event listeners, static collections, closures, and caches that keep an object reachable will leak even in a garbage-collected runtime. The fix is to give every allocation a deterministic release point tied to a well-defined lifetime or ownership boundary.

## Key Principles

- Bind every allocation to a deterministic release point tied to a scope, object lifetime, or explicit ownership boundary, using the language's automatic resource-management construct
- Do not rely solely on garbage collection to prevent leaks; unintended references keep objects reachable indefinitely regardless of GC
- Bound the size and lifetime of any long-lived collection (cache, session store, subscriber list) with explicit eviction, expiry, or capacity limits
- Release resources on every exit path, including error and exception paths, not only the success path
- Break reference cycles or use weak references where a relationship should not, by itself, keep an object alive

## Remediation Steps

- Locate - Identify the allocation point and confirm no corresponding release exists on some or all code paths
- Trace the reference lifecycle - Determine what holds a reference to the object and why that reference outlives its intended use
- Identify the unsafe pattern - Look for missing cleanup calls, unbounded collections keyed by unpredictable input, unregistered event listeners or callbacks, or reference cycles
- Replace with deterministic lifetime management - Tie the resource to a scope or ownership boundary so release happens automatically when that scope ends, on every exit path
- Bound long-lived structures - Add capacity limits, expiry, or weak references to any cache, registry, or subscriber list that grows with usage
- Add secondary controls - Monitor memory and resource growth metrics in production as an early warning layer
- Test - Profile heap and memory usage under sustained load before and after the fix and confirm usage stabilizes instead of growing unbounded
