# CWE-416: Use After Free - C

## LLM Guidance

Use-after-free is dereferencing a pointer after `free()` has run on it. C tracks no pointer validity, so nothing stops a stale address being read, written, or passed on after the allocator has reused the block. The fix is to decide which single component owns each allocation and give it a release function taking `T **`, so releasing nulls the owner's variable rather than a copy; nulling is what turns a stray later use into an immediate fault instead of silent corruption of whatever now occupies that memory.

## Key Principles

- Null the pointer at the moment of release, through a release function that takes the address of the caller's variable (`void close_session(struct Session **sp)`)
- Whose variable gets nulled is the part that must be right: `&session` works where `session` is the caller's own local, and does nothing where `session` is that function's *parameter* - then it nulls a copy and leaves the original caller dangling
- Nulling reaches exactly one variable; a copy held in a struct field, a work-queue entry, or a callback context is still dangling, so single ownership is the fix and nulling is the mitigation
- Where a pointer must outlive the call that hands it out - a deferred callback, a queued job - pass a handle or index the receiver can revalidate rather than a raw address
- A NULL dereference faults at a known address with a stack trace pointing at the use; a use-after-free typically shows no symptom until an unrelated structure misbehaves, so failing fast is a real improvement even though both are bugs
- After `realloc()`, the old pointer is invalid whether or not the block moved - assign the result and stop using the previous variable
- Watch for the pointer being freed inside a callee while the caller keeps using it, which is the same defect with the ownership boundary crossed
- Build tests with `-fsanitize=address`, which reports the use, the free, and the allocation stacks; Valgrind is a useful independent check

## Taint Sinks

Any dereference after `free()` - `memcpy()`/`strcpy()` into the pointer, a struct member access, passing it to another function, `realloc()` of an already-freed pointer, a linked-list traversal that frees while iterating

## Remediation Steps

- Locate - find each `free()` on the pointer named in the finding and every subsequent use of that pointer or a copy of it
- Trace data flow - identify every variable holding the same address (locals, struct fields, callback contexts, container entries) and which of them outlive the release
- Identify the unsafe pattern - a use reachable after a release, a callee that frees a pointer its caller keeps, or an iteration that frees the node it is about to advance through
- Replace with the safe pattern - single ownership plus a `T **` release function; capture `node->next` before freeing `node` when walking a list
- Bind, encode, validate, or authorize - replace raw pointers that cross an asynchronous boundary with a revalidatable handle
- Harden configuration - build and test with `-fsanitize=address`, and keep allocator hardening enabled in test environments
- Test - exercise the early-release path and the normal path in the same run, and confirm ASan reports no use-after-free; assert that a second call to the release function is a no-op
