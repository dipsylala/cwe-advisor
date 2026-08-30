# CWE-415: Double Free - C

## LLM Guidance

Double free is `free()` running twice on the same pointer with no intervening allocation. C has no ownership tracking, so it almost always reduces to unclear responsibility: an error path and the normal path both release, or a linked structure is traversed twice, each believing it must free the same block. Deciding that exactly one function owns each allocation is the fix; nulling the pointer after release is what makes a stray second call harmless.

## Key Principles

- Give every allocation exactly one release function, and write that ownership into the signature: `void buffer_free(Buffer **bufp)` takes the address of the caller's variable so it can null it
- A `T *` parameter is a copy - nulling it is invisible the moment the function returns, so a release function taking `T *` cannot protect its caller
- `free(NULL)` is defined as doing nothing (C11 7.22.3.3p2), so a `if (p != NULL)` guard before `free(p)` is noise that implies a check is required when it is not
- Nulling protects only the variable whose address was passed: a copy stored in a struct field, a callback context, or a second local is still dangling, which is why ownership is the fix and nulling is the mitigation
- Nulling before free is not a concurrency fix: the load of the pointer and the store of NULL are two separate, non-atomic operations, so another thread or signal handler can still observe the old value between them. Making that safe needs a lock held across the whole teardown, or an atomic exchange to claim the pointer first
- Where a structure is genuinely reachable from more than one owner, nulling one handle is not enough at all - it needs a reference count, decremented by each release and freed only at zero, or a design where exactly one component holds the data and the others ask it for access
- A `SAFE_FREE(p)` macro must expand its argument only where a plain lvalue is passed - it evaluates the argument twice, so never call it on an expression with side effects
- Set the pointer to NULL immediately after the release, in the same statement sequence, not at the end of the function where an early `return` skips it
- On an error path, release once and jump to a single cleanup label rather than freeing in each branch
- Build tests with `-fsanitize=address`, which reports "attempting double-free" with both the allocation and the two release stacks

## Taint Sinks

`free()`, `realloc()` with a pointer that may already be freed, a custom `*_free()`/`*_destroy()` called from more than one path

## Remediation Steps

- Locate - find every `free()` on the pointer named in the finding, including calls inside cleanup helpers and error paths
- Trace data flow - establish which function is meant to own the allocation and which paths can reach a release, particularly the error path plus the normal path
- Identify the unsafe pattern - two releases reachable on the same execution, or a pointer freed by a callee and again by the caller
- Replace with the safe pattern - give the allocation a single owner and a `T **` release function that nulls the caller's variable
- Bind, encode, validate, or authorize - consolidate error handling on one cleanup label so each resource is released exactly once
- Harden configuration - build and test with `-fsanitize=address`; keep the allocator's own hardening (glibc tcache/`MALLOC_CHECK_`) enabled in test environments
- Test - exercise the error path and the success path in the same run, and confirm ASan reports no double-free; assert that calling the release function twice is a no-op
