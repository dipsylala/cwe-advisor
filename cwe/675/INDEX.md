# CWE-675: Multiple Operations on Resource in Single-Operation Context

## LLM Guidance

This weakness occurs when a resource - a lock, memory allocation, file or socket handle, or connection - is released, freed, or finalized more than once in a context that expects exactly one such operation. Because normal-path and error/exception-path cleanup are often written separately, a resource freed on success can be freed again in a catch block, or the reverse. The fix is to ensure exactly one code path owns the release, preferably by tying it to scope exit, and to make manual release idempotent when scope-bound cleanup is not available.

## Key Principles

- Give every resource a single, clearly identified owner responsible for releasing it
- Prefer scope-bound or automatic resource management, tied to block or object lifetime, over manual release calls scattered across normal and error paths
- Where manual release is unavoidable, make the release function idempotent by checking and updating an explicit released-state marker as one step
- In concurrent code, guard the released-state check and the release itself with the same synchronization used to guard the resource
- Do not duplicate cleanup logic between a success path and its corresponding error or exception handler; route both through one release point
- Treat a resource passed through multiple layers without a clear ownership handoff as a warning sign for this weakness
- MITRE classes this as a caller ignoring a "call this once" contract rather than a lifetime bug, so prefer the child: multiple locks CWE-764, multiple unlocks CWE-765, multiple releases of a handle CWE-1341, a duplicated `free()` CWE-415, multiple binds to one port CWE-605, and double decoding of the same data CWE-174
- The shape that survives testing releases correctly on the success path *and* in the handler, and the handler cannot tell which has already run: if the operation throws, only the handler releases and the test passes; if anything after the release throws, both run and the second acts on a handle that no longer refers to what the variable says
- Make repeat calls a safe no-op - clear the variable at release, or use a scope guard that runs exactly once - rather than relying on callers never invoking cleanup twice

## Remediation Steps

- Locate - identify where the resource is acquired (lock, allocation, handle, connection) and every code path that releases it
- Trace data flow - enumerate normal completion, error handlers, exception paths, destructors, and explicit cleanup calls that each perform a release
- Identify the unsafe pattern - more than one of those paths releases the same resource, or nothing tracks whether release already happened
- Replace with the safe pattern - use scope-bound resource management so release happens automatically and exactly once regardless of exit path
- Where scope-bound management is unavailable, make release idempotent with an explicit state check guarded by the same synchronization as the resource
- Add secondary controls - a single, clear ownership handoff whenever a resource is passed between layers or threads
- Test - force every error and exception path and confirm the resource releases exactly once; call release twice deliberately and confirm the second call is a safe no-op
