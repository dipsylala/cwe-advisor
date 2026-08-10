# CWE-364: Signal Handler Race Condition

## LLM Guidance

This weakness occurs when a signal handler accesses or modifies shared state - global variables, non-reentrant library calls, dynamic memory - that the interrupted main program may also be using, creating a race between the handler and the code it interrupted. The core fix is to keep signal handlers minimal and limited to async-signal-safe operations, communicating with the main program through a safe mechanism such as an atomic flag or self-pipe rather than directly touching shared, non-atomic state.

## Key Principles

- Keep signal handlers as short as possible; do only what must happen immediately in signal context
- Use only async-signal-safe functions inside a handler; avoid memory allocation, non-reentrant library calls, stdio, and most locking primitives
- Communicate with the rest of the program through a single flag of a signal-safe atomic type, or a self-pipe/eventfd, rather than mutating arbitrary shared state directly
- Do not acquire a lock inside a signal handler that the interrupted code might already hold, since this can deadlock the process
- Mask or block signals during critical sections of the main program where a handler interrupting mid-update would leave inconsistent state
- Prefer synchronous signal handling (blocking signals and consuming them with a wait primitive on a dedicated thread) over asynchronous handlers when the platform supports it

## Remediation Steps

- Locate - Find signal handler registrations and the body of each handler function
- Trace data flow - Identify what shared variables, resources, or functions the handler touches, and what else in the program touches the same state
- Identify the unsafe pattern - A handler calling non-async-signal-safe functions, writing to non-atomic shared state, or the handler and main code accessing shared state without synchronization
- Replace with the safe pattern - Reduce the handler to setting an atomic flag or writing to a self-pipe, and move the real work into the main event loop that checks the flag
- Add secondary controls - Mask signals during sensitive sections of the main program, and audit remaining shared state for reentrancy issues
- Test - Trigger the signal repeatedly and concurrently with the operation it can interrupt, and check for corrupted state, crashes, or deadlocks under stress
