# CWE-364: Signal Handler Race Condition

## LLM Guidance

A signal arrives between two machine instructions rather than between two statements, so no point in the interrupted code is safe by construction - a struct half updated, a pointer half written, an allocator's free list mid-relink. The fix is the opposite of the thread case: a mutex taken in a handler deadlocks against the code it interrupted, because both run on the same thread. This is frequently the root cause behind a CWE-415 double free or a CWE-416 use-after-free, and a handler calling any non-async-signal-safe function is CWE-479.

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
