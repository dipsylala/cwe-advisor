# CWE-401: Missing Release of Memory after Effective Lifetime (Memory Leak)

## LLM Guidance

Usually a lingering reference rather than a literal missing free, which is why it happens in garbage-collected runtimes too: an event listener, a static collection, a closure, or an unbounded cache keeps the object reachable, and collection never applies to it.

## Key Principles

- Bind every allocation to a deterministic release point tied to a scope, object lifetime, or explicit ownership boundary, using the language's automatic resource-management construct
- Bound the size and lifetime of any long-lived collection (cache, session store, subscriber list) with explicit eviction, expiry, or capacity limits
- Release resources on every exit path, including error and exception paths, not only the success path
- Break reference cycles or use weak references where a relationship should not, by itself, keep an object alive
- Do not count on a finalizer or cleaner: no language guarantees one runs before exit, and pooled connections, locks, and native handles behind a thin binding often have no fallback at all - so the best case is late and the worst is never
- With a listener the reference points the opposite way to the dependency: the component needs the publisher, but subscribing makes the long-lived publisher hold the short-lived component, so lifetime is decided by the wrong end
- Watch the resource counters as well as the heap - file descriptors, pooled connections, goroutines or threads - since those exhaust long before memory does

## Remediation Steps

- Locate - Identify the allocation point and confirm no corresponding release exists on some or all code paths
- Trace the reference lifecycle - Determine what holds a reference to the object and why that reference outlives its intended use
- Identify the unsafe pattern - Look for missing cleanup calls, unbounded collections keyed by unpredictable input, unregistered event listeners or callbacks, or reference cycles
- Replace with deterministic lifetime management - Tie the resource to a scope or ownership boundary so release happens automatically when that scope ends, on every exit path
- Bound long-lived structures - Add capacity limits, expiry, or weak references to any cache, registry, or subscriber list that grows with usage
- Add secondary controls - Monitor memory and resource growth metrics in production as an early warning layer
- Test - Profile heap and memory usage under sustained load before and after the fix and confirm usage stabilizes instead of growing unbounded
