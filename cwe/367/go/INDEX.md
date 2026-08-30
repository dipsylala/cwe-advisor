# CWE-367: Time-of-check Time-of-use Race Condition - Go

## LLM Guidance

Go makes concurrency cheap, so shared state is reached from many goroutines by default rather than by exception, and the scheduler can place another goroutine between a check and the action it guards at any point. Two shapes account for most findings: a read-modify-write on a shared variable where the read and the write are separate operations, and a filesystem check followed by an operation on the same path. Make the check and the update one operation - a compare-and-swap, a mutex-held critical section, or a conditional database update.

## Key Principles

- Use `atomic.CompareAndSwap*` in a retry loop when the invariant covers a single word: the write lands only if the value is still what the check saw, and a losing goroutine re-reads rather than applying a stale decision. `atomic.Int64` (Go 1.19+) gives the same behaviour without raw pointer arguments; bound the retry loop with a max attempt count or context deadline under heavy contention, since an unbounded CAS retry can starve a goroutine indefinitely
- Use a `sync.Mutex` when the critical section covers more than one variable - two coordinated CAS operations are not atomic together
- `sync.Map`'s `LoadOrStore` and `CompareAndSwap` exist precisely so a check and a store are one call; a `Load` followed by a `Store` is not
- Across processes or instances, neither a mutex nor an atomic helps: push the invariant into the database as a conditional `UPDATE ... WHERE` and use the affected-row count as the result
- For filesystem work, resolve the path once: `os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)` fails if the name exists, rather than checking with `os.Stat` first
- Use `os.CreateTemp`/`os.MkdirTemp` rather than composing a name and creating it separately
- Go 1.24's `os.Root`/`os.OpenInRoot` confines path resolution to a directory and resists symlink swaps between calls
- Run the tests with `-race`: the detector finds the unsynchronised read-modify-write shapes directly, though it cannot see a filesystem race

## Taint Sinks

`os.Stat()` followed by `os.Open`/`os.Create`, a read then write on a shared variable, `sync.Map.Load` followed by `Store`, a database read followed by a separate write, `ioutil.TempFile` name reuse

## Remediation Steps

- Locate - find checks followed by a dependent action on state reachable from more than one goroutine, request, or process
- Trace data flow - determine what else writes that state, and whether the deployment runs more than one instance
- Identify the unsafe pattern - a separate read and write, a `sync.Map` load-then-store, or a `Stat`-then-open on a path
- Replace with the safe pattern - `CompareAndSwap` in a loop for a single word, a mutex for a wider critical section, or a conditional `UPDATE` for cross-process state
- Bind, encode, validate, or authorize - add the database constraint that encodes the invariant, so a future code path cannot bypass it
- Harden configuration - use exclusive-create flags and `os.Root` for file access, and keep shared directories unwritable by other users
- Test - run with `-race` under concurrent load, and for the cross-process case exercise several instances against one database and assert the invariant holds
