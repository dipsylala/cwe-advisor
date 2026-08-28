# CWE-401: Missing Release of Memory After Effective Lifetime - C#

## LLM Guidance

The garbage collector handles managed memory, so this finding in .NET is about `IDisposable` resources that are never disposed - file handles, streams, database connections, `HttpClient` handlers, unmanaged buffers - and about managed objects kept reachable by an event subscription or a static collection. The consequences are connection-pool depletion and handle exhaustion long before memory runs out. Use `using` declarations for everything disposable, unsubscribe from events, and bound anything static.

## Key Principles

- Wrap every `IDisposable` in a `using` declaration (`using var conn = ...;`) or a `using` block, so `Dispose()` runs on every path including an exception
- A finalizer is not a substitute: it runs at an unspecified time and is not guaranteed to run at all, so the handle is held until then
- Implement the dispose pattern properly for a class holding unmanaged resources - a public `Dispose()`, a `protected virtual Dispose(bool)`, and `GC.SuppressFinalize(this)` - and prefer `SafeHandle` over a raw `IntPtr`
- Unsubscribe from events in the same lifecycle step that subscribed: a publisher holds a strong reference to every subscriber, so a long-lived publisher keeps short-lived subscribers alive
- Implement `IAsyncDisposable` and `await using` for resources with asynchronous teardown rather than blocking in `Dispose()`
- `HttpClient` is the classic inversion: dispose it per request and you exhaust sockets in `TIME_WAIT`; use `IHttpClientFactory` (or a single long-lived instance) instead
- Bound every static or singleton-held collection and cache - a static field is a GC root, so entries live for the process's lifetime unless evicted (`MemoryCache` with a size limit and expiry)
- Dispose `CancellationTokenSource`, and unregister `CancellationToken` callbacks, when the operation ends - a long-lived token accumulates registrations
- Diagnose with `dotnet-counters`/`dotnet-gcdump` and the pool's own counters rather than by inspection

## Taint Sinks

`new FileStream`/`StreamReader` without `using`, `SqlConnection`/`SqlCommand`/`SqlDataReader`, `new HttpClient()` per call, `+=` event subscription without a matching `-=`, `static Dictionary`/`List` accumulating entries, `CancellationTokenSource`

## Remediation Steps

- Locate - find `IDisposable` allocations not covered by `using`, event subscriptions, and static mutable collections
- Trace data flow - identify what holds each object: a pool, a publisher's invocation list, a static field, a cache entry
- Identify the unsafe pattern - a missing `Dispose`, an asymmetric `+=`/`-=`, an unbounded static collection, or a per-call `HttpClient`
- Replace with the safe pattern - `using` declarations, matched unsubscription, `IHttpClientFactory`, and a size-bounded `MemoryCache`
- Bind, encode, validate, or authorize - bound anything sized by request data so a client cannot drive retention
- Harden configuration - enable connection-pool diagnostics, set cache size limits in configuration, and treat CA2000/CA1816 analyzer warnings as errors
- Test - run a sustained load through the code path and confirm handle counts, pool usage, and heap size return to baseline afterwards
