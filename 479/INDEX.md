# CWE-479: Signal Handler Use of a Non-Reentrant Function

## LLM Guidance

This weakness occurs when a signal handler calls a function that is not async-signal-safe, such as one that allocates memory, acquires a lock, or relies on internal static state. Because a signal can interrupt program execution at any point, including in the middle of that same function, the result is undefined behavior: deadlocks, heap corruption, or unpredictable, timing-dependent crashes. The fix is to restrict every signal handler to functions documented as async-signal-safe and defer everything else to normal execution.

## Key Principles

- Primary defence: a signal handler sets only an atomic flag or performs a single async-signal-safe write, nothing else
- Avoid calling memory allocation, buffered/formatted output, or locking functions from within a handler
- Perform the substantive work (allocation, logging, cleanup) in the normal execution context after the handler returns, triggered by the flag it set
- Prefer handler-free signal delivery where the platform supports it, since it removes the async-signal-safety question entirely
- Review every registered handler against the platform's async-signal-safe function list, not only the one a scanner flagged
- Defence-in-depth: use a thread or data-race sanitizer to catch races between a handler and the code it interrupts
- A handler does not run alongside the program, it runs inside it: the kernel suspends the thread between two instructions and runs the handler on that same thread, so it begins with whatever the program was halfway through still halfway through - a free list partly relinked, a buffer partly flushed, an object partly constructed
- That is why a lock does not help: calling back into the code that owns the mid-update state re-enters it, and a mutex the interrupted code already holds deadlocks
- The same defect with a thread as the concurrent context rather than a signal is CWE-663, and a handler racing the main program over shared state generally is CWE-364; the restriction is identical in all of them

## Remediation Steps

- Locate - Identify every registered signal handler (source) and every function it calls, directly or indirectly (sink)
- Trace data flow - Follow each call from the handler through any helper functions to confirm none touch non-reentrant internal state
- Identify the unsafe pattern - A handler calling allocation, buffered I/O, locking, or another function absent from the async-signal-safe list
- Replace with the safe pattern - Reduce the handler to a single atomic flag write or an async-signal-safe write; move the real work to the main loop
- Add secondary controls - Enable a thread/data-race sanitizer and review for state accessed both inside and outside handlers
- Test - Trigger the signal repeatedly under load and with a sanitizer enabled to expose timing-dependent failures, then re-scan to confirm resolution
