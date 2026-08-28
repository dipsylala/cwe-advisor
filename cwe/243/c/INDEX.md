# CWE-243: Creation of chroot Jail Without Changing Working Directory - C

## LLM Guidance

`chroot()` remaps `/` for the calling process and does nothing to its current working directory. A process that calls `chroot()` and then uses relative paths can still reach anything outside the new root that its file permissions allow, so the jail exists in name only until `chdir("/")` moves the working directory inside it. The correct sequence is close inherited descriptors, `chroot()`, `chdir("/")` immediately, then drop privileges - and each step fails closed.

## Key Principles

- Call `chdir("/")` immediately after `chroot()`, before any file access; a relative path resolved from the old working directory walks straight out of the jail
- Close inherited file descriptors first: `chroot()` does not close them, and a directory handle opened before the call is a route back out through `fchdir()`. Use `closefrom(3)` (glibc 2.34+, the BSDs), `close_range(3, ~0U, 0)`, or a loop over `/proc/self/fd`
- Drop privileges after entering the jail - a process that keeps root can call `chroot()` again from inside and escape, so the confinement is only meaningful once the effective and saved UIDs are unprivileged
- Drop supplementary groups with `setgroups()` before `setgid()`, and `setgid()` before `setuid()`; reversing the order leaves the process without the privilege needed to complete the earlier step
- Check the return value of every one of these calls and exit on failure - a `chroot()` that silently failed leaves the process running unconfined with the code believing it is jailed
- Verify the drop actually happened (attempt to regain the old UID and confirm it fails) rather than trusting the call sequence
- `chroot` is a filesystem-namespace control only: it does not restrict network access, signals, `/proc`, or IPC. Where stronger isolation is required, prefer a container, a mount namespace, or `pledge`/`seccomp`

## Taint Sinks

`chroot()` without a following `chdir("/")`, `fchdir()` on a pre-chroot descriptor, `setuid()`/`setgid()` calls whose return values are unchecked, relative-path `open()`/`fopen()` after `chroot()`

## Remediation Steps

- Locate - find every `chroot()` call and the statements that follow it
- Trace data flow - identify file accesses after the call that use relative paths, and any descriptors opened before it that remain open
- Identify the unsafe pattern - a missing or delayed `chdir("/")`, retained privileges, or an unchecked return value on any step
- Replace with the safe pattern - close descriptors, `chroot()`, `chdir("/")`, `setgroups()`, `setgid()`, `setuid()`, each checked
- Bind, encode, validate, or authorize - confirm the privilege drop by attempting to regain the previous UID and requiring that it fail
- Harden configuration - prefer namespace or container isolation where available; treat `chroot` as one layer rather than the boundary
- Test - from inside the jail, attempt to open a path outside the new root by a relative path and by a retained descriptor, and assert both fail
