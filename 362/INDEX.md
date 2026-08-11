# CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')

## LLM Guidance

This weakness occurs when multiple threads, processes, or requests access the same shared resource - a counter, balance, file, database row, cache entry, or session - and the interleaving of their operations produces an incorrect or exploitable result, such as a lost update, a double-spend, or a security check that no longer holds by the time it is acted on. The core remediation is to make access to the resource atomic: serialize it behind an in-process lock, mutex, or atomic primitive when it lives in memory, or push the atomicity to the datastore via row locks, atomic increment/decrement, unique constraints, or optimistic locking with a version column when it is shared across processes or server instances. See CWE-367 for a check followed by a separate use of the same value (file existence before open, permission check before action), and CWE-366 for unsynchronized shared state confined to a single process's threads.

## Key Principles

- Treat the shared resource's full check-and-act or read-modify-write sequence as a single atomic unit; synchronizing only part of it still leaves a race window
- Use in-process synchronization primitives (mutex, lock, semaphore, atomic operation) for state shared within a single process; never assume single-threaded execution without verifying it for that runtime
- For state shared across processes, servers, or requests, push atomicity to the datastore: row-level locks, atomic increment/decrement, unique constraints, or optimistic locking via a version or timestamp column
- Never rely on request timing, UI throttling, or client-side controls to prevent concurrent access; concurrency must be enforced server-side
- Keep locked or transactional critical sections minimal but complete: begin protection before the first read of the shared state and release only after the final write
- Design idempotency keys and conflict detection as defence-in-depth for operations that cannot be fully serialized

## Remediation Steps

- Locate - Find resources read and written by more than one thread, process, or request: counters, balances, files, database rows, cache keys, session data
- Trace data flow - Identify where a value is read, a decision or computation is made, and the value is written back, and determine what else can access that resource during the interval
- Identify the unsafe pattern - Unsynchronized read-modify-write, a lock or transaction held for only part of the sequence, or a check performed separately from the action it guards
- Replace with the safe pattern - Wrap the full critical section in a lock/mutex or atomic operation in-process, or move the operation into a single atomic database statement or locked transaction
- Add secondary controls - Unique constraints, idempotency keys, or optimistic locking with a version column to detect and reject conflicting concurrent writes
- Harden configuration - Ensure the same lock, mutex, or transaction isolation level protects the resource consistently across all code paths, including error and retry paths
- Test - Run concurrent threads, processes, or requests against the same resource and verify the final state is always correct with no lost updates, duplicated effects, or bypassed checks
