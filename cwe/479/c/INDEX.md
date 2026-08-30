# CWE-479: Signal Handler Use of a Non-Reentrant Function - C

## LLM Guidance

A signal handler runs asynchronously and can interrupt the main program - or another handler - mid-operation. If it then calls a function that is not reentrant (one holding static state, internal locks, or its own buffers), it observes or corrupts state the interrupted code was in the middle of using. The outcomes range from garbled output to deadlock to heap corruption, and they are timing-dependent. Restrict every handler to the functions POSIX documents as async-signal-safe, and defer everything else to the normal execution context.

## Key Principles

- The safe set is small and explicit: `write()`, `_exit()`, `signal()`/`sigaction()`, assignment to `volatile sig_atomic_t`, and the other functions POSIX lists as async-signal-safe. Treat anything not on that list as unsafe, including apparently trivial calls
- `printf`/`fprintf` are not safe: `stdio` streams carry internal buffers and locks, so a handler interrupting a print can produce interleaved output or deadlock on the stream lock
- `malloc`/`free` are not safe: the allocator's structures may be mid-update when the signal arrives
- `localtime`, `asctime`, `getpwnam` and similar return pointers to static buffers, so a handler using them overwrites what the interrupted code was reading; `strerror` gained a per-thread buffer in glibc 2.32 but neither it nor any `_r` variant is on the POSIX async-signal-safe list - reentrant is not the same guarantee
- Use `write(STDERR_FILENO, msg, len)` for handler output, and `_exit()` rather than `exit()` (which runs `atexit` handlers and flushes streams) - `write()` can itself set `errno`, so save it on entry and restore it before returning from anything beyond a single unconditional call
- `syslog()` is MITRE's own example for this CWE precisely because it doesn't look dangerous - it formats into a buffer, holds a static connection to `/dev/log`, and allocates, none of which is async-signal-safe
- Reduce the handler to a flag assignment and do the real work in the main loop; this is what makes the safety property obvious rather than a per-call judgement
- Register with `sigaction()` and block the signals the handler serves in `sa_mask` so it cannot re-enter itself
- Where a handler must do more, prefer `signalfd()` (Linux) or a self-pipe, which turn signal delivery into a readable event handled by ordinary code

## Taint Sinks

`printf()`/`fprintf()`/`puts()` in a handler, `malloc()`/`free()`, `exit()`, `strerror()`, `localtime()`/`asctime()`, `getpwnam()`, `syslog()`, any mutex operation, any function not on the POSIX async-signal-safe list

## Remediation Steps

- Locate - find every handler registered with `signal()`/`sigaction()` and read its body and everything it calls
- Trace data flow - identify each call the handler makes, including through helper functions, and check it against the POSIX async-signal-safe list
- Identify the unsafe pattern - a non-async-signal-safe call reachable from the handler, or a handler doing cleanup work that belongs in the main loop
- Replace with the safe pattern - assign a `volatile sig_atomic_t` flag in the handler and move the work to the main loop; use `write()` where output from the handler is genuinely required
- Bind, encode, validate, or authorize - initialise the `struct sigaction` with `sigemptyset(&sa.sa_mask)`, block handled signals with `sigaddset()`, and set `SA_RESTART` - it does not restart everything: `select`/`poll`/`epoll_wait`, `pause`/`sigsuspend`, timed socket calls, System V IPC, and sleep functions still return early regardless
- Harden configuration - consider `signalfd`/self-pipe delivery to remove the asynchronous context entirely
- Test - deliver the signal repeatedly during heavy `stdio` and allocation activity and confirm no interleaved output, deadlock, or corruption; assert the deferred work still runs
