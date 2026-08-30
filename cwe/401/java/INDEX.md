# CWE-401: Missing Release of Memory After Effective Lifetime - Java

## LLM Guidance

Java's garbage collector reclaims unreachable objects, so the finding here is about objects that stay *reachable* longer than they are needed, and about non-memory resources the collector does not manage at all. The recurring shapes are an unclosed `AutoCloseable` (stream, connection, statement), an unbounded static collection or cache, a listener never unregistered, and a `ThreadLocal` never removed on a pooled thread. The fixes are try-with-resources, bounded caches with eviction, symmetric register/unregister, and weak or soft references where a cache must not pin its entries.

## Key Principles

- Wrap every `AutoCloseable` in try-with-resources; declaring several in one statement closes them in reverse order even when the body throws
- A `finally { close(); }` written by hand is the pattern try-with-resources replaces - it is easy to get wrong when `close()` itself throws, which suppresses the original exception
- Bound every cache: `LinkedHashMap` with `removeEldestEntry` and the access-order constructor (`new LinkedHashMap<>(capacity, 0.75f, true)`), Caffeine or Guava with a `maximumSize` and an expiry. An unbounded `static Map` is the classic Java leak because a static field is a GC root
- Unregister listeners, callbacks and observers in the same lifecycle method that registered them, and keep a reference to the exact instance so removal actually matches
- Call `ThreadLocal.remove()` in a `finally` on any pooled thread - a container thread outlives the request and keeps the value alive
- Use `WeakReference`/`WeakHashMap` for a cache keyed by an object whose lifetime someone else owns, and `SoftReference` where the entry is a recomputable optimisation
- A non-static inner class instance always retains the enclosing instance, whether or not its body ever uses it. A lambda is different: it captures the enclosing instance only if its body references `this`, an instance field, or an instance method - a lambda referencing only local variables or static members holds no reference to it at all. Check what the lambda body actually touches before assuming a long-lived registry entry keeps the component alive
- Close connection-pool resources back to the pool rather than the underlying socket, and set a connection leak-detection threshold in the pool configuration
- Diagnose with a heap dump and dominator tree (Eclipse MAT, JFR's old-object sample), not by inspection - the retaining path is usually not where the allocation is

## Taint Sinks

`new FileInputStream`/`FileReader` without try-with-resources, `Connection`/`PreparedStatement`/`ResultSet`, `static Map`/`List` accumulating entries, `addListener`/`addObserver` without a matching remove, `ThreadLocal.set()` on a pooled thread, `ExecutorService` never shut down

## Remediation Steps

- Locate - find `AutoCloseable` acquisitions not in a try-with-resources, static mutable collections, and listener registrations
- Trace data flow - identify what keeps each object reachable: a static field, a collection entry, a listener list, a `ThreadLocal`, a captured `this`
- Identify the unsafe pattern - an unclosed resource, an unbounded collection, or an asymmetric register/unregister pair
- Replace with the safe pattern - try-with-resources for resources, a size- and time-bounded cache for accumulating maps, and matched removal for listeners
- Bind, encode, validate, or authorize - bound anything sized by request data (a per-session map, a batch accumulator) so a client cannot drive retention
- Harden configuration - enable pool leak detection, set `-XX:+HeapDumpOnOutOfMemoryError`, and cap cache sizes in configuration rather than in code comments
- Test - run a sustained load exercising the code path and confirm heap usage returns to baseline after a full GC; assert the cache respects its bound
