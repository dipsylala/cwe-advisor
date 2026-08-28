# CWE-364: Signal Handler Race Condition - C

## LLM Guidance

POSIX signal handlers run asynchronously and can interrupt normal execution - or another handler - at essentially any instruction, and C provides no automatic protection. A handler that touches shared state or calls a non-reentrant function can corrupt data, deadlock, or double-free depending on exactly when the signal arrives, and the failure is timing-dependent so it rarely shows up in normal testing. Restrict handlers to the small set of async-signal-safe functions and set a flag the main loop acts on.

## Key Principles

- Do only async-signal-safe work in the handler: assign to a `volatile sig_atomic_t`, call `write()`, call `_exit()`. Everything else - `malloc`, `free`, `printf`, mutex locks, most library calls - is deferred to the normal context
- `malloc`/`free` in a handler is the classic instance: the allocator's internal state may be mid-update at the moment the signal arrives, so the handler's call corrupts it
- Register with `sigaction()` rather than `signal()`, whose semantics vary across platforms, and set `SA_RESTART` so interrupted syscalls resume
- Initialise `sa_mask` with `sigemptyset()` and add every signal the handler serves with `sigaddset()`, so one cannot interrupt the handler for another and re-enter it
- A flag is not a substitute for synchronization between threads - `sig_atomic_t` guarantees an uninterrupted read or write of that one object, nothing more; do not build multi-variable state in a handler
- Use `_exit()` rather than `exit()` when terminating from a handler: `exit()` runs `atexit` handlers and flushes streams, neither of which is safe from an interrupted context
- Where a handler must report, `write(STDERR_FILENO, msg, len)` is safe and `printf` is not
- Prefer `signalfd()` (Linux) or a self-pipe so signals are delivered to the main loop as readable events and no asynchronous context exists at all

## Taint Sinks

`malloc()`/`free()` in a handler, `printf()`/`fprintf()`, `exit()`, mutex lock/unlock, any shared data structure mutated from a handler, `signal()` registration

## Remediation Steps

- Locate - find every `signal()`/`sigaction()` registration and read the body of each handler
- Trace data flow - identify shared state the handler touches and library calls it makes, including indirect ones through helpers
- Identify the unsafe pattern - non-async-signal-safe calls, multi-step state updates, or a handler that performs the cleanup work itself
- Replace with the safe pattern - reduce the handler to a single `volatile sig_atomic_t` assignment and move the work into the main loop
- Bind, encode, validate, or authorize - block the handled signals in `sa_mask` and register with `sigaction` plus `SA_RESTART`
- Harden configuration - consider `signalfd`/self-pipe delivery so the work runs in ordinary code with no handler context at all
- Test - send the signals repeatedly and concurrently under load (and under ThreadSanitizer where threads are involved) to expose the race, and confirm the process shuts down cleanly rather than deadlocking
