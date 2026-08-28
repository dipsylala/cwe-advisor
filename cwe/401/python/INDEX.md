# CWE-401: Missing Release of Memory After Effective Lifetime - Python

## LLM Guidance

Leaks in Python are usually resource leaks rather than memory-management ones: unclosed files, connections and sockets, and unbounded caches. Reference cycles belong here as a delay rather than a leak - CPython reference-counts and also runs a cycle detector, so a cycle is collected on a later periodic pass, and everything it holds stays held until then. That delay is why file-handle exhaustion and connection-pool depletion are the failures that actually show up. Use `with` for every resource and bound every cache.

## Key Principles

- Use a `with` statement for every file, socket, connection, cursor, and lock; it closes on the exception path too, which a trailing `f.close()` does not
- CPython's refcounting makes a dropped reference close promptly, but that is an implementation detail - on PyPy or under a cycle it does not, so do not rely on it
- Give your own resource-owning classes `__enter__`/`__exit__` (or `@contextlib.contextmanager`) so callers can use them the same way, and `contextlib.ExitStack` with `stack.enter_context()` where the number of resources is dynamic
- Bound caches: `functools.lru_cache(maxsize=N)` rather than `maxsize=None`, and a size or TTL limit on any dict used as a cache. An unbounded module-level dict lives for the process
- `lru_cache` on a method keeps `self` alive for as long as the entry is cached - cache a module-level function of the key instead, or use `weakref`
- Break cycles with `weakref` for back-references (parent pointers, observer registries) so the collector is not the only thing that can reclaim them
- Close database cursors and sessions explicitly at request end - an ORM session that stays open holds a pooled connection and its identity map
- `del` removes a name, not an object; it helps only when it drops the last reference
- Diagnose with `tracemalloc` snapshots, `gc.get_objects()` counts by type, and the pool's own metrics rather than by inspection

## Taint Sinks

`open()` without `with`, `socket.socket()`, a database connection or cursor closed only on the success path, `functools.lru_cache(maxsize=None)`, a module-level `dict` used as a cache, an event or observer registry holding strong references

## Remediation Steps

- Locate - find resource acquisitions not wrapped in `with`, unbounded caches, and registries that accumulate entries
- Trace data flow - identify which paths close each resource, and what keeps each cached object reachable
- Identify the unsafe pattern - a close on the success path only, an unbounded cache, or a strong back-reference forming a cycle
- Replace with the safe pattern - a `with` statement (or `ExitStack`), a bounded `lru_cache`, and `weakref` for back-references
- Bind, encode, validate, or authorize - bound anything keyed by request data so a client cannot drive retention
- Harden configuration - set pool sizes and timeouts explicitly, and enable `PYTHONDEVMODE`/`-W error::ResourceWarning` in tests so an unclosed file fails the test
- Test - run the code path in a loop and assert open file descriptors and pool checkouts return to baseline; use `tracemalloc` to compare snapshots
