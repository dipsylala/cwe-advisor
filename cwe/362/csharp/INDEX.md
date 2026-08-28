# CWE-362: Race Condition - C#

## LLM Guidance

Shared mutable state on a singleton service, static field, or in-memory cache is the usual source of this weakness in .NET, especially in ASP.NET Core where services registered with singleton or scoped-but-shared lifetimes are invoked concurrently by request threads. The `lock` statement (backed by `Monitor`) is the primary defence for synchronous critical sections, but `lock` cannot wrap an `await`; async code must use `SemaphoreSlim.WaitAsync()`/`Release()` instead. For single-variable counters, `System.Threading.Interlocked` (`Interlocked.Increment`, `Interlocked.CompareExchange`) avoids locking entirely, and for database-backed shared state, EF Core's `[ConcurrencyCheck]`/`RowVersion` optimistic concurrency or a `SELECT ... FOR UPDATE`-equivalent transaction is preferred over an application-level lock.

## Key Principles

- Use `lock (object)` to protect a synchronous critical section end-to-end; never lock on `this`, a boxed value, or a string literal, since those can be inadvertently shared
- Never use `lock` around code containing `await`; use `new SemaphoreSlim(1, 1)` with `WaitAsync()` in a `try` and `Release()` in a `finally` for async critical sections instead
- Use `Interlocked.Increment`/`Interlocked.CompareExchange` for simple counters and flags instead of a lock when only one variable changes atomically
- Replace plain `Dictionary`/`List` shared across requests with `System.Collections.Concurrent` types (`ConcurrentDictionary`, `ConcurrentQueue`), and still guard compound check-then-act sequences explicitly
- For EF Core entities, add a `[Timestamp]`/`RowVersion` byte array or `[ConcurrencyCheck]` property so `SaveChanges()` throws `DbUpdateConcurrencyException` on a conflicting concurrent write
- Do not assume a singleton-registered service is race-free; ASP.NET Core invokes singleton services concurrently across all in-flight requests
- `ConcurrentDictionary`'s compound operations exist because two correct calls are not an atomic pair: use `GetOrAdd`, `AddOrUpdate` or `TryUpdate` (which takes the expected current value) rather than `TryGetValue` followed by an assignment
- `AddOrUpdate` and `GetOrAdd` may invoke the factory more than once under contention, so the factory must be side-effect free
- Prefer the `Lock` type (.NET 9+) or `lock` over raw `Monitor.Enter`, which needs a matching `Monitor.Exit` in a `finally` to survive an exception
- A lock guards one process only - for state in a database or shared across instances, use a transaction with the appropriate isolation or a conditional update

## Taint Sinks

Unsynchronized `Dictionary<>`/`List<>` mutation, singleton/static field read-modify-write without `lock`, `lock` wrapping `await`

## Remediation Steps

- Locate - Find fields on singleton/static services, or shared collections, read and written by concurrent request handlers or background tasks
- Trace data flow - Identify where a value is read, a decision made, and the value written back, and what else can reach the same field concurrently
- Identify the unsafe pattern - An unsynchronized read-modify-write, `lock` wrapped around an `await`, or a plain collection mutated from multiple requests
- Replace with the safe pattern - Wrap synchronous critical sections in `lock`, use `SemaphoreSlim` for async critical sections, or use `Interlocked` for single-variable updates
- Bind, encode, validate, or authorize - For EF Core-backed state, add a concurrency token and catch `DbUpdateConcurrencyException` to retry or reject the conflicting write
- Harden configuration - Ensure the same lock/semaphore instance protects the resource consistently across all code paths, including exception paths
- Test - Drive concurrent calls (`Task.WhenAll` over multiple callers) against the same resource and confirm no lost updates and that concurrency conflicts surface as a handled exception, not silent data loss
