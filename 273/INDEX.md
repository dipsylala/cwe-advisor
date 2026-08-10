# CWE-273: Improper Check for Dropped Privileges

## LLM Guidance

This weakness occurs when a process attempts to drop elevated privileges (setuid/setgid, administrative rights, impersonation) but never verifies the drop succeeded, or drops privileges in the wrong order, leaving the process running with unintended elevated access. The core fix is to check the return value of every privilege-dropping call, verify the resulting privilege level, and fail closed if the drop cannot be confirmed.

## Key Principles

- Always check the return status of privilege-drop calls; treat failure as fatal, not a warning to log and continue past
- Drop group privileges before user privileges - dropping user privileges first can prevent the group drop from succeeding
- Verify the actual resulting privilege level after the drop (re-query effective/saved IDs) rather than assuming the call worked
- Drop privileges as early as possible after the elevated operation completes, minimizing the window of elevated execution
- Apply least privilege to the elevated section itself: elevate only for the specific operation that requires it
- Treat unconfirmed privilege state as untrusted - do not proceed to handle untrusted input or perform further operations until the drop is verified

## Remediation Steps

- Locate - Find code paths that acquire elevated privileges (setuid, runas, sudo, impersonation) and any subsequent privilege-drop calls
- Trace the privilege lifecycle - Identify where privileges are elevated, where they should be dropped, and what runs after the drop
- Identify the unsafe pattern - Drop call result ignored, incorrect drop order (user before group), or no drop performed before untrusted operations
- Replace with the safe pattern - Check the return value of the drop call, then explicitly re-verify the current privilege level before continuing
- Fail closed - If the drop cannot be confirmed, terminate the process rather than continuing with an unknown privilege state
- Add secondary controls - Apply least privilege to the elevated section, log privilege transitions, and use OS-level sandboxing or capability restrictions where available
- Test - Simulate a failed privilege drop (mock or force the underlying call to fail) and confirm the process aborts instead of continuing privileged
