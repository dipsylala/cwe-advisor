# CWE-367: Time-of-check Time-of-use Race Condition - JavaScript

## LLM Guidance

A single-threaded event loop rules out two lines of synchronous code interleaving and leaves the kind of race that matters here. Every `await` is a yield: the handler suspends, other requests run to completion, and the state checked before the `await` may be different when it resumes. The rule is mechanical - any authorization, balance, or existence check followed by an `await` before its use is a time-of-check time-of-use window, and the window is as long as the awaited operation.

## Key Principles

- Re-validate immediately before the privileged step rather than reusing a value read before an `await`; the earlier read is a snapshot, not a fact
- Better still, remove the gap: make the check part of the write with a conditional update (`UPDATE ... WHERE balance >= $1`) or a transaction, and use the affected-row count as the decision
- Node's `worker_threads` and multi-process deployments (`cluster`, PM2, containers) mean an in-process guard protects nothing; a promise-based mutex helps within one process only
- Pass an idempotency key to operations that must not repeat, so a retry after a lost race cannot double-apply
- For filesystem work, resolve once: `fs.open(path, 'wx', 0o600)` (or `fsPromises.open` with `'wx'`) fails if the file exists, rather than checking with `fs.existsSync` first; `fs.existsSync` followed by `fs.writeFile` resolves the path twice
- Prefer `try`/`catch` on the operation over a pre-check - the error reports state at the moment of the call
- Use the database's own locking (`SELECT ... FOR UPDATE` inside a transaction, or a unique constraint) for cross-request invariants, since only the database sees all workers
- Beware `await` inside a loop over shared state: each iteration re-enters the event loop, so a collection read before the loop can be stale by the second iteration

## Taint Sinks

`fs.existsSync()`/`fs.access()` followed by a write, a token or role check separated from the guarded call by an `await`, a read-then-write on a shared object or cache, a balance check followed by a separate update, `fs.mkdtemp` name reuse

## Remediation Steps

- Locate - find every check whose result is used after an intervening `await`
- Trace data flow - determine what else can change that state between the check and the use, including other requests and other workers
- Identify the unsafe pattern - reuse of a pre-`await` snapshot for an authorization or balance decision, or an existence check before a file operation
- Replace with the safe pattern - re-validate at the point of use, or fold the condition into the write and act on the row count
- Bind, encode, validate, or authorize - add the database constraint that encodes the invariant, and pass an idempotency key where a repeat would be harmful
- Harden configuration - use exclusive-create flags for files, and do not rely on in-process locks in a clustered deployment
- Test - fire concurrent requests from multiple workers (not just parallel promises in one process) and assert the invariant holds
