# CWE-272: Least Privilege Violation

## LLM Guidance

This weakness appears when a process acquires an elevated privilege to perform one specific operation, such as binding a low network port or making a single administrative call, and then continues running with that privilege afterward instead of dropping it the instant the operation completes. Because the elevated access outlives the task that needed it, any other vulnerability in the same process afterward executes with that same elevated access, widening a contained bug into a privilege-escalation path. The remediation is to acquire the privilege for the narrowest possible window, drop it permanently right after the privileged operation finishes, and confirm the drop actually took effect before proceeding.

## Key Principles

- Primary defence: drop elevated privilege permanently immediately after the privileged operation completes, before handling any untrusted input.
- Drop every component of the elevated identity together (effective, saved, supplementary groups, and any OS capabilities); dropping only the most visible one leaves an unenforced path back to full privilege.
- Perform the drop unconditionally on every exit path from the privileged operation, including error and exception paths, not only the success path.
- Do not assume a privilege-drop call succeeded; verify the drop took effect (for example, confirm the privilege cannot be re-acquired) before continuing.
- Where the platform supports it, prefer a narrower mechanism that avoids needing full elevation at all, such as a capability scoped to exactly one action, over acquiring and then dropping broad privilege.
- Distinguish this from a component that is configured to run with excess privilege for its entire lifetime with no specific privileged operation to point to; that broader, standing condition is a different weakness requiring a different fix.

## Remediation Steps

- Locate - Find every place a process acquires elevated privilege to perform a specific operation.
- Trace data flow - Identify everything that executes after the privileged operation and confirm whether it still runs under the elevated identity.
- Identify the unsafe pattern - Confirm there is no privilege-drop call immediately following the operation, or that the drop is incomplete (only the effective identity, leaving groups or capabilities attached).
- Replace with the safe pattern - Add an unconditional, complete privilege drop immediately after the privileged operation, covering effective, saved, and supplementary identity components, on every exit path.
- Add secondary controls - Add a verification step after the drop that confirms the elevated privilege can no longer be re-acquired, failing closed if it can.
- Test - After the code path that should drop privilege completes, attempt the privileged operation again and confirm it fails; confirm both the effective and saved identity reflect the unprivileged account.
- Verify - Re-scan with the tool that reported the finding to confirm it is resolved.
