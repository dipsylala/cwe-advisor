# CWE-557: Concurrency Issues

## LLM Guidance

Concurrency issues arise when multiple threads or processes access shared mutable state without adequate synchronization, producing race conditions, check-then-act gaps, non-atomic updates, or deadlocks. When the affected state guards a security decision - an authorization check, a balance, a resource limit - a race can let an attacker bypass the check entirely rather than merely corrupt data. The core fix is to make the security-relevant check and the action it gates a single atomic unit, using the runtime's synchronization or concurrency-safe primitives rather than ad hoc coordination.

## Key Principles

- Treat every check-then-act sequence on shared state as one atomic unit, especially when the check is a security decision
- Prefer built-in atomic types and thread-safe collections over manual locking for simple counters and flags
- Guard all reads of shared state with the same synchronization used for writes, not writes alone
- Acquire multiple locks in a consistent global order across the codebase to avoid deadlock
- Do not dismiss a rarely-triggered race as low risk; timing-dependent bugs are exploitable, not merely flaky
- Apply defense-in-depth: idempotency keys, unique constraints, or rate limiting reduce impact if a race slips through
- MITRE prohibits this category as a mapping target, so a finding reported here has not been classified yet: work out the shape first - the general race is CWE-362, a signal handler is CWE-364, state shared between threads of one process is CWE-366, check-then-use is CWE-367, and channel setup is CWE-421
- Acquire multiple locks in one global order (by a stable id) so no cycle of waiters can form; deadlock needs each thread to hold what the next one waits for
- Guard reads with the same lock as writes - a read left unsynchronized can observe a partially-updated value even when every write is protected

## Remediation Steps

- Locate - identify shared mutable state accessed by more than one thread, process, or request handler
- Trace data flow - find check-then-act sequences and non-atomic read-modify-write operations touching that state
- Identify the unsafe pattern - a security check separated in time from the action it gates, or an update composed of multiple unsynchronized steps
- Replace with the safe pattern - wrap the check and the action in the same lock or transaction, or replace manual coordination with an atomic primitive or thread-safe data structure
- Address deadlock risk - if locks are introduced, order their acquisition consistently across every call path
- Add secondary controls - idempotency keys, unique database constraints, or rate limiting to bound the impact of any residual race
- Test - run the affected path under concurrent load and confirm the security invariant holds and no deadlock occurs
