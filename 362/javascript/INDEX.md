# CWE-362: Race Condition - JavaScript

## LLM Guidance

JavaScript's single-threaded event loop guarantees that synchronous code runs to completion without interruption, but this does not make `async`/`await` code race-free: any `await` is a suspension point where another callback, timer, or request handler can run and mutate shared state before the current function resumes. The classic pattern is reading a value, awaiting an I/O call (a database query, an API call), and writing an updated value back - two concurrent calls can interleave between the read and the write and both act on stale data. For state confined to a single Node.js process, serialize the critical section with a promise-based mutex such as the `async-mutex` package; for state shared across processes, workers, or server instances, push the atomicity into the datastore (an atomic `UPDATE ... SET balance = balance - $1 WHERE id = $2 AND balance >= $1`, MongoDB `findOneAndUpdate` with `$inc`, or a distributed lock such as Redis `SET key value NX`).

## Key Principles

- Treat every `await` between a read and a write of shared state as a potential race window, even though JavaScript is single-threaded
- Use a promise-based mutex (`async-mutex`'s `Mutex`/`Semaphore`, via `runExclusive()`) to serialize an async critical section within one process
- Prefer pushing the read-modify-write into a single atomic database operation over an in-process lock whenever the resource is a database row, since a lock only protects one process
- For state shared across Node.js `worker_threads`, use `Atomics` operations (`Atomics.add`, `Atomics.compareExchange`) on a `SharedArrayBuffer`, not a plain shared object
- Never assume a `Promise.all` of independent async operations preserves ordering on shared state; each awaited step is an interleaving point
- For cross-process or multi-instance deployments, use a distributed lock (Redis `SET NX`/`redlock`) or datastore-level atomicity rather than an in-process mutex, which only protects one process

## Taint Sinks

Module-level variable mutated after an `await`, unguarded `Promise.all` writes to a shared object/cache, read-modify-write on a database row without a mutex

## Remediation Steps

- Locate - Find module-level variables, cached objects, or database rows read and written by more than one concurrent async call
- Trace data flow - Identify every `await` between the read of the shared value and the write-back, and what other requests or callbacks can run during that suspension
- Identify the unsafe pattern - A read-await-write sequence with no serialization, or a check-then-act split across two awaited calls
- Replace with the safe pattern - Wrap the critical section in a promise-based mutex (`mutex.runExclusive()`), or replace the read-then-write with a single atomic database statement
- Bind, encode, validate, or authorize - For database-backed shared state, use a conditional atomic `UPDATE` (`WHERE balance >= $1`) and check the affected row count instead of a separate read and write
- Harden configuration - For multi-instance or multi-process deployments, replace an in-process mutex with a distributed lock or datastore atomicity
- Test - Fire concurrent async calls (`Promise.all`) against the same resource and confirm the final state is always correct with no lost updates
