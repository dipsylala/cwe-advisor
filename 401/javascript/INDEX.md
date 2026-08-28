# CWE-401: Missing Release of Memory After Effective Lifetime - JavaScript

## LLM Guidance

JavaScript is garbage collected, so the finding is about references that keep objects reachable past their useful life: an event listener never removed (which also keeps the detached DOM node and everything the handler closes over), a `setInterval` never cleared, a growing module-level cache, and closures retaining large objects. In long-running single-page applications and Node processes this is a steady climb to memory exhaustion. Remove what you added, in the lifecycle hook that mirrors where you added it.

## Key Principles

- Store the bound handler in a field and pass that same reference to `removeEventListener` - a fresh `.bind(this)` at removal time does not match the one that was added, so nothing is removed
- Prefer `AbortController`: pass `{ signal }` to `addEventListener` and call `abort()` once to detach every listener registered with it
- Clear timers: keep the id from `setInterval`/`setTimeout` and call `clearInterval`/`clearTimeout` in the teardown path, including the error path
- Use the framework's own teardown - React's `useEffect` cleanup return, Vue's `beforeUnmount`, Angular's `ngOnDestroy` - rather than relying on the element being removed from the DOM
- Bound every cache: an unbounded `Map` at module scope is reachable for the process's lifetime. Add a size limit with eviction, or use `WeakMap`/`WeakSet` where the key's lifetime is owned elsewhere
- `WeakRef` and `FinalizationRegistry` are for caches and diagnostics, not for cleanup you depend on - collection timing is not guaranteed
- In Node, remove listeners from long-lived emitters (`process`, a shared socket, an `EventEmitter` in a module) when the consumer goes away; `emitter.setMaxListeners` warnings are a symptom worth reading
- Detached DOM nodes are the characteristic browser leak: a node removed from the document but still referenced by a handler, a closure, or an array stays alive with its whole subtree
- Diagnose with a heap snapshot comparison (Chrome DevTools "Detached" filter, `node --inspect` and `--heapsnapshot-signal`), not by inspection

## Taint Sinks

`addEventListener` without a matching `removeEventListener`, `setInterval`/`setTimeout` without a clear, module-scope `Map`/`Array` accumulating entries, `emitter.on()` on a long-lived emitter, closures capturing large objects, `global`/`window` assignments

## Remediation Steps

- Locate - find listener registrations, timers, subscriptions, and module-level collections
- Trace data flow - identify what holds each object reachable: a listener list, a timer callback, a closure, a cache entry, a global
- Identify the unsafe pattern - an add with no matching remove, a timer with no clear, or a collection with no bound
- Replace with the safe pattern - `AbortController` for listeners, stored ids for timers, teardown in the framework's lifecycle hook, and a bounded or weak cache
- Bind, encode, validate, or authorize - bound anything sized by user activity (per-connection buffers, per-session maps) so a client cannot drive retention
- Harden configuration - set a heap limit (`--max-old-space-size`) so a leak surfaces as a restart rather than a stall, and monitor RSS over time
- Test - mount and unmount the component (or open and close the connection) repeatedly under a heap snapshot and confirm the detached-node and listener counts return to baseline
