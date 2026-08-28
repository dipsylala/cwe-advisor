# CWE-401: Missing Release of Memory After Effective Lifetime - Go

## LLM Guidance

Go collects unreachable memory, so the finding here is about goroutines that block forever, resources that are never closed, and references that stay reachable. A leaked goroutine keeps its whole stack and everything it closes over alive for the process's lifetime, and an unclosed `http.Response.Body` holds a connection out of the pool. Use `defer` at the point of acquisition, give every goroutine a way to exit (a context, a closed channel, a bounded receive), and bound anything that accumulates.

## Key Principles

- `defer resp.Body.Close()` immediately after checking the error from `http.Get`/`Do` - without it the connection is not returned to the pool and the transport opens a new one each time
- Read the body to completion (or `io.Copy(io.Discard, resp.Body)`) before closing, or the connection cannot be reused even though it was closed
- Every goroutine needs a guaranteed exit: pass a `context.Context` and select on `ctx.Done()`, or ensure the channel it reads from is closed. A goroutine blocked on a send to a channel nobody receives from never returns
- Use `context.WithTimeout`/`WithCancel` for any operation that can block, and call the returned `cancel` with `defer` even on the success path - not calling it leaks the timer and the context's goroutine
- `defer` runs at function return, not at end of block: a `defer` inside a loop accumulates until the function exits, so wrap the body in a function or close explicitly in the loop
- Close what you open - files, `sql.Rows`, `net.Conn`, tickers (`ticker.Stop()`) - and check the error from `Close()` on writes, where it reports a failed flush
- A slice re-sliced from a large backing array keeps the whole array alive; copy the sub-slice when the original is large and short-lived
- Bound accumulating maps and caches, especially ones keyed by request data, and delete entries when the owning connection or session ends
- Diagnose with `pprof` goroutine and heap profiles and `runtime.NumGoroutine()` over time, rather than by inspection; a goroutine count that only rises is the signature

## Taint Sinks

`http.Get`/`Do` without `defer resp.Body.Close()`, `os.Open`/`sql.Query` without a close, `go func(){}` with no exit path, `context.WithCancel` whose `cancel` is not called, `time.NewTicker` without `Stop()`, a map that only grows

## Remediation Steps

- Locate - find resource acquisitions without a paired `defer`, goroutine launches, and long-lived maps
- Trace data flow - for each goroutine, establish how it terminates; for each resource, establish which paths close it
- Identify the unsafe pattern - a missing `Close`, a goroutine with no cancellation path, a `defer` inside a loop, or an unbounded map
- Replace with the safe pattern - `defer` at acquisition, `http.NewRequestWithContext` so the request honours cancellation, a context with cancellation for every goroutine, and an explicit close inside loops
- Bind, encode, validate, or authorize - bound queues, buffers, and caches sized by request data
- Harden configuration - set client timeouts (`http.Client{Timeout: ...}`) so a slow peer cannot pin a goroutine indefinitely, and expose `pprof` in non-production builds
- Test - run the code path in a loop and assert `runtime.NumGoroutine()` returns to its starting value, and use `goleak` in tests to fail on a leaked goroutine
