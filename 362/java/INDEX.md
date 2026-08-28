# CWE-362: Race Condition - Java

## LLM Guidance

Shared mutable state accessed from multiple threads - a field on a singleton bean, a static counter, an in-memory cache map - is the most common source of this weakness in Java, since neither the JVM nor common frameworks (Spring's default singleton scope) provide synchronization automatically. The primary fix is the `synchronized` keyword or `java.util.concurrent.locks.ReentrantLock` around the full read-modify-write sequence, or `java.util.concurrent.atomic` classes (`AtomicInteger`, `AtomicLong`, `AtomicReference`) for single-variable updates. For state backed by a relational database, prefer `SELECT ... FOR UPDATE` in a transaction or JPA/Hibernate `@Version` optimistic locking over an application-level lock.

## Key Principles

- Use `synchronized` methods/blocks or `ReentrantLock` to protect the entire critical section, not just the read or the write in isolation
- Use `java.util.concurrent.atomic` (`AtomicInteger.incrementAndGet()`, `AtomicReference.compareAndSet()`) for single-variable counters and flags instead of a lock
- Replace plain `HashMap`/`ArrayList` shared across threads with `ConcurrentHashMap` or `Collections.synchronizedList`, and still guard compound operations (check-then-put) explicitly since these are only atomic per-call, not across calls
- For JPA/Hibernate entities, add a `@Version` column for optimistic locking, or use `SELECT ... FOR UPDATE` (`@Lock(LockModeType.PESSIMISTIC_WRITE)`) when a conflict must block rather than fail
- Do not assume a Spring `@Service` or `@Component` bean is race-free because a single instance handles all requests; singleton beans are shared across all concurrent threads
- Keep synchronized blocks short and always release locks in a `finally` block when using explicit `Lock` objects
- `ConcurrentHashMap.compute()`/`computeIfAbsent()`/`putIfAbsent()` are the atomic forms; a `get()` followed by a `put()` races even on that class
- Release a `ReentrantLock` in a `finally` block, or an exception leaves it held and every later caller blocks
- Optimistic locking is a retry contract, not a guarantee: treat `ObjectOptimisticLockingFailureException` as a signal to re-read and retry rather than as a 500
- `SERIALIZABLE` isolation makes the database enforce the invariant, at the cost of serialization failures the application must be prepared to retry

## Taint Sinks

`HashMap.put()`/`get()` shared across threads, `ArrayList.add()` without synchronization, instance/static field `+=` without `synchronized`

## Remediation Steps

- Locate - Find instance or static fields, maps, or collections read and written by more than one thread (servlet/controller handler threads, executor tasks, scheduled jobs)
- Trace data flow - Identify where a value is read, a decision made, and the value written back, and what other threads can reach the same field concurrently
- Identify the unsafe pattern - An unsynchronized read-modify-write, a `HashMap` shared without synchronization, or a check-then-act split across separate statements
- Replace with the safe pattern - Wrap the critical section in `synchronized` or a `ReentrantLock`, or replace a single-variable update with an `Atomic*` class method
- Bind, encode, validate, or authorize - For database-backed shared state, use `SELECT ... FOR UPDATE` in a transaction or add a JPA `@Version` field for optimistic concurrency control
- Harden configuration - Ensure the same lock object or `@Version` strategy protects the resource consistently, including exception paths
- Test - Exercise the code with a thread pool driving concurrent calls against the same resource and confirm no lost updates and, for optimistic locking, that `OptimisticLockException` is handled by retry or a clear error
