# CWE-272: Least Privilege Violation

## LLM Guidance

The privilege was legitimately needed for one operation - binding a low port, a single administrative call - and outlives it. Where the component is simply configured to run elevated for its whole lifetime with no such operation to point to, that is CWE-250, and the fix there is a lower-privilege identity from startup rather than a drop.

## Key Principles

- Primary defence: drop elevated privilege permanently immediately after the privileged operation completes, before handling any untrusted input.
- Drop every component of the elevated identity together (effective, saved, supplementary groups, and any OS capabilities); dropping only the most visible one leaves an unenforced path back to full privilege.
- Perform the drop unconditionally on every exit path from the privileged operation, including error and exception paths, not only the success path.
- Do not assume a privilege-drop call succeeded; verify the drop took effect (for example, confirm the privilege cannot be re-acquired) before continuing.
- Where the platform supports it, prefer a narrower mechanism that avoids needing full elevation at all, such as a capability scoped to exactly one action, over acquiring and then dropping broad privilege.
- Order the drop correctly, or the code looks complete and is not: `setgroups()`/`setgid()` must run *before* `setuid()`, since once the user id is gone those calls have no privilege left to succeed with - and an unchecked failure there silently leaves the groups attached
- `seteuid()` changes only what the process currently acts as and leaves the saved user id at the privileged value, so a later call can silently re-acquire it; the permanent form (`setuid`) is what the drop needs

## Remediation Steps

- Locate - Find every place a process acquires elevated privilege to perform a specific operation.
- Trace data flow - Identify everything that executes after the privileged operation and confirm whether it still runs under the elevated identity.
- Identify the unsafe pattern - Confirm there is no privilege-drop call immediately following the operation, or that the drop is incomplete (only the effective identity, leaving groups or capabilities attached).
- Replace with the safe pattern - Add an unconditional, complete privilege drop immediately after the privileged operation, covering effective, saved, and supplementary identity components, on every exit path.
- Add secondary controls - Add a verification step after the drop that confirms the elevated privilege can no longer be re-acquired, failing closed if it can.
- Test - After the code path that should drop privilege completes, attempt the privileged operation again and confirm it fails; confirm both the effective and saved identity reflect the unprivileged account.
- Verify - Re-scan with the tool that reported the finding to confirm it is resolved.
