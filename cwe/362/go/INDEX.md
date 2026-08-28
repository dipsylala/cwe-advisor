# CWE-362: Race Condition - Go

## LLM Guidance

Goroutines make concurrent access trivial to introduce and easy to miss: a shared variable, map, or struct field read and written from multiple goroutines without synchronization produces a data race, detectable with `go test -race` or `go run -race`. The primary fix is `sync.Mutex`/`sync.RWMutex` around the full read-modify-write sequence, or `sync/atomic` (including the typed `atomic.Int64`/`atomic.Bool` added in Go 1.19+) for simple counters and flags. When the shared state is a database row rather than in-memory, use a transaction with `SELECT ... FOR UPDATE` or a single atomic `UPDATE` statement instead of a Go-level lock.

## Key Principles

- Protect the entire critical section with `sync.Mutex.Lock()`/`Unlock()` (or `sync.RWMutex` for read-heavy access), not just the individual field accesses
- Use `sync/atomic` (`atomic.Int64.Add`, `atomic.CompareAndSwap`) for single-variable counters and flags instead of a mutex, but switch to a mutex once more than one field must change together
- Never write to a plain `map` from multiple goroutines, even with a mutex elsewhere in the codebase protecting a different field; use `sync.Map` or a mutex-guarded map consistently
- For state shared across processes or instances (not just goroutines), use database-level atomicity: `SELECT ... FOR UPDATE` in a transaction, or an atomic `UPDATE table SET balance = balance - $1 WHERE id = $2 AND balance >= $1`
- Pass data ownership through channels where the design allows it, instead of sharing memory and synchronizing access to it
- Run `go test -race` (or build with `-race`) in CI to catch missed synchronization before it reaches production

## Taint Sinks

Unsynchronized `map` writes from a `go func() {...}`, package-level `var` read-modify-write, struct field mutation without `sync.Mutex`

## Remediation Steps

- Locate - Find struct fields, package-level variables, maps, or slices read and written by more than one goroutine
- Trace data flow - Identify goroutine launch points (`go func() {...}`) and every path that reads or mutates the shared value
- Identify the unsafe pattern - An unsynchronized read-modify-write, a `map` write without a mutex, or a check-then-act split across two unguarded statements
- Replace with the safe pattern - Wrap the critical section in `sync.Mutex.Lock()`/`defer Unlock()`, or replace a single-variable read-modify-write with `sync/atomic`
- Bind, encode, validate, or authorize - For database-backed shared state, replace the read-then-write with a transaction using `SELECT ... FOR UPDATE` or a conditional atomic `UPDATE`
- Harden configuration - Ensure the same mutex instance guards the same field everywhere it is touched, including error-return paths
- Test - Run `go test -race` under concurrent goroutines exercising the same resource and confirm no data race is reported and the final value is always correct
