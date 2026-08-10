# CWE-366: Race Condition within a Thread

## LLM Guidance

This weakness occurs when multiple threads access or update shared state - variables, collections, counters, cached values - without synchronization, allowing operations from different threads to interleave and produce corrupted, inconsistent, or security-bypassing results. The core fix is to identify the shared state and protect the read-modify-write sequence around it with a lock, atomic operation, or thread-safe data structure so the sequence behaves as a single atomic step.

## Key Principles

- Protect the entire read-modify-write sequence on shared state with a lock or atomic primitive, not just the individual reads and writes
- Prefer atomic operations (compare-and-swap, atomic increment/decrement) for simple counters and flags, and locks for compound operations
- Use thread-safe or concurrent data structures instead of adding ad hoc locking around ordinary collections
- Minimize shared mutable state; prefer immutable data or thread-local storage where the design allows it
- Keep locked critical sections as short as possible to limit contention, but never so short that part of the operation is left unprotected
- Ensure the same lock consistently protects the same shared state everywhere it is accessed, including error and exception paths

## Remediation Steps

- Locate - Find the shared resource (variable, collection, counter, cached value) and every code path across threads that reads or writes it
- Trace data flow - Identify sequences where a value is read, a decision is made, and the value is then updated, especially where these steps are not adjacent
- Identify the unsafe pattern - An unsynchronized read-modify-write, a plain collection accessed from multiple threads, or a lock held for only part of the sequence
- Replace with the safe pattern - Wrap the full read-modify-write sequence in a lock, or replace it with a single atomic operation
- Add secondary controls - Use thread-safe collections for shared containers and document the locking protocol so future changes do not reintroduce a gap
- Test - Run the code under concurrent load with multiple threads performing the same operation, verify the final state is always consistent, and use race-detection tooling where available
